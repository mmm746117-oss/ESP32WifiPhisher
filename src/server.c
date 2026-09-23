#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_ota_ops.h>
#include <lwip/sockets.h>
#include <cJSON.h>
#include "evil_twin.h"
#include "server.h"
#include "server_api.h"
#include "TaskManager.h"


static const char *TAG = "WEBSERVER";
static httpd_handle_t server = NULL;
static uint8_t attack_scheme = 0xff;
static QueueHandle_t ws_frame_queue = NULL;
static TaskHandle_t ws_frame_process_task_handle = NULL;


static void ws_send_work(void *arg)
{
    ws_frame_req_t *r = (ws_frame_req_t *)arg;
    httpd_ws_frame_t out = {
        .final = true,
        .fragmented = false,
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)r->payload,
        .len = r->len ? r->len : strlen(r->payload)
    };
    /* BROADCAST */
    if (r->fd == -1) {
        size_t fds = 10;
        int client_fds[10];
        if (httpd_get_client_list(r->hd, &fds, client_fds) == ESP_OK) {
            for (int i = 0; i < fds; i++) {
                if (httpd_ws_get_fd_info(r->hd, client_fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
                    esp_err_t ret = httpd_ws_send_frame_async(r->hd, client_fds[i], &out);
                    if (ret != ESP_OK) httpd_sess_trigger_close(r->hd, client_fds[i]);
                }
            }
        }
    } else {
        esp_err_t ret = httpd_ws_send_frame_async(r->hd, r->fd, &out);
        if (ret != ESP_OK) httpd_sess_trigger_close(r->hd, r->fd);
    }
    if (r->need_free && r->payload) cJSON_free(r->payload);
    free(r);
}


static void ws_frame_process_task(void *pvParameter)
{
    (void)pvParameter;
    ws_frame_req_t ws_frame;
    while (1) {
        if (xQueueReceive(ws_frame_queue, &ws_frame, portMAX_DELAY) == pdTRUE) {
            switch (ws_frame.frame_type) {
            case WS_RX_FRAME:
                http_api_parse(&ws_frame);
                if (ws_frame.payload) free(ws_frame.payload);
                break;
            case WS_TX_FRAME: {
                ws_frame_req_t *heap_req = malloc(sizeof(ws_frame_req_t));
                if (heap_req) {
                    memcpy(heap_req, &ws_frame, sizeof(ws_frame_req_t));
                    if (httpd_queue_work(ws_frame.hd, ws_send_work, heap_req) != ESP_OK) {
                        if (heap_req->payload && heap_req->need_free) cJSON_free(heap_req->payload);
                        free(heap_req);
                    }
                } else if (ws_frame.payload && ws_frame.need_free) {
                    cJSON_free(ws_frame.payload);
                }
                break;
            }
            default: break;
            }
        }
    }
}


/* Receive a raw application image and write it directly to the inactive OTA slot.
 * The client sends the .bin as the request body (not multipart/form-data). */
static esp_err_t ota_upload_handler(httpd_req_t *req)
{
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OTA partition available");
        return ESP_FAIL;
    }
    if (req->content_len == 0 || (size_t)req->content_len > update_partition->size) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid firmware size");
        return ESP_FAIL;
    }

    esp_ota_handle_t ota_handle = 0;
    esp_err_t err = esp_ota_begin(update_partition, req->content_len, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");
        return err;
    }

    char buffer[4096];
    size_t received = 0;
    while (received < (size_t)req->content_len) {
        int read_len = httpd_req_recv(req, buffer,
                                      ((size_t)req->content_len - received > sizeof(buffer)) ?
                                      sizeof(buffer) : (size_t)req->content_len - received);
        if (read_len <= 0) {
            if (read_len == HTTPD_SOCK_ERR_TIMEOUT) continue;
            err = ESP_FAIL;
            break;
        }
        err = esp_ota_write(ota_handle, buffer, read_len);
        if (err != ESP_OK) break;
        received += (size_t)read_len;
    }

    if (err == ESP_OK) err = esp_ota_end(ota_handle);
    else esp_ota_abort(ota_handle);
    if (err == ESP_OK) err = esp_ota_set_boot_partition(update_partition);

    if (err != ESP_OK || received != (size_t)req->content_len) {
        ESP_LOGE(TAG, "OTA upload failed after %u bytes: %s", (unsigned)received, esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid firmware image");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Firmware uploaded; rebooting\"}");
    ESP_LOGI(TAG, "OTA complete (%u bytes), rebooting", (unsigned)received);
    vTaskDelay(pdMS_TO_TICKS(250));
    esp_restart();
    return ESP_OK;
}


static esp_err_t captive_portal_redirect(httpd_req_t *req)
{
    ESP_LOGD(TAG, "Captive portal captured url: %s", req->uri);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}


static esp_err_t cors_prevention_handler(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    return httpd_resp_send(req, NULL, 0);
}


static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) return ESP_OK;
    httpd_ws_frame_t frame = {0};
    frame.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) return ret;
    if (frame.type == HTTPD_WS_TYPE_PING) {
        httpd_ws_frame_t pong = {.type = HTTPD_WS_TYPE_PONG, .payload = NULL, .len = 0};
        return httpd_ws_send_frame(req, &pong);
    }
    if (frame.type == HTTPD_WS_TYPE_CLOSE || frame.len == 0) return ESP_OK;
    if (frame.len >= 4096) return ESP_FAIL;
    uint8_t *buf = calloc(1, frame.len + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    frame.payload = buf;
    ret = httpd_ws_recv_frame(req, &frame, frame.len);
    if (ret != ESP_OK) { free(buf); return ret; }
    ws_frame_req_t ws_req = {
        .hd = req->handle, .fd = httpd_req_to_sockfd(req), .frame_type = WS_RX_FRAME,
        .payload = (char *)buf, .len = frame.len, .need_free = true
    };
    if (xQueueSend(ws_frame_queue, &ws_req, pdMS_TO_TICKS(100)) != pdTRUE) {
        free(buf);
        return ESP_FAIL;
    }
    return ESP_OK;
}


static esp_err_t redirect_handler(httpd_req_t *req)
{
    char filepath[128] = "/spiffs";
    char buf[1024];
    size_t n;
    const char *uri = req->uri;
    if (strcmp(uri, "/hotspot-detect.html") == 0 || strcmp(uri, "/library/test/success.html") == 0 ||
        strcmp(uri, "/generate_204") == 0 || strcmp(uri, "/gen_204") == 0 || strcmp(uri, "/connecttest.txt") == 0 ||
        strcmp(uri, "/redirect") == 0 || strcmp(uri, "/ncsi.txt") == 0 || strcmp(uri, "/check_network_status.txt") == 0 ||
        strcmp(uri, "/canonical.html") == 0 || strncmp(uri, "/success.txt", 12) == 0) {
        return captive_portal_redirect(req);
    }
    if (strcmp(uri, "/") == 0) {
        switch (attack_scheme) {
        case FIRMWARE_UPGRADE: uri = "/fwupgrade/index.html"; break;
        case WEB_NET_MANAGER: uri = "/netmng/index.html"; break;
        case PLUGIN_UPDATE: uri = "/plugin.html"; break;
        case OAUTH_LOGIN: uri = "/oauth/index.html"; break;
        default: uri = "/admin.html"; break;
        }
    }
    strlcat(filepath, uri, sizeof(filepath));
    FILE *f = fopen(filepath, "r");
    if (!f) return captive_portal_redirect(req);
    httpd_resp_set_type(req, mime_from_path(filepath));
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) { fclose(f); return ESP_FAIL; }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}


esp_err_t ws_send_command_to_queue(ws_frame_req_t *_req)
{
    if (!ws_frame_queue) return ESP_FAIL;
    _req->frame_type = WS_TX_FRAME;
    return xQueueSend(ws_frame_queue, _req, pdMS_TO_TICKS(100)) == pdTRUE ? ESP_OK : ESP_FAIL;
}

esp_err_t ws_send_broadcast_to_queue(ws_frame_req_t *_req)
{
    if (!ws_frame_queue || uxQueueSpacesAvailable(ws_frame_queue) == 0) return ESP_FAIL;
    _req->frame_type = WS_TX_FRAME;
    return xQueueSend(ws_frame_queue, _req, 0) == pdTRUE ? ESP_OK : ESP_FAIL;
}


void http_server_start(void)
{
    if (server != NULL) return;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.ctrl_port = 81;
    config.server_port = 80;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_open_sockets = 10;
    config.max_resp_headers = 16;
    config.recv_wait_timeout = 60;
    config.send_wait_timeout = 10;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 16;
    ESP_ERROR_CHECK(httpd_start(&server, &config));

    ws_frame_queue = xQueueCreate(WS_FRAME_QUEUE_LENGTH, sizeof(ws_frame_req_t));
    if (!ws_frame_queue) return;
    task_manager_create_task(ws_frame_process_task, "ws_frame_process_task", 4096, NULL, 5, &ws_frame_process_task_handle);

    httpd_uri_t cors_preflight_uri = {.uri = "/*", .method = HTTP_OPTIONS, .handler = cors_prevention_handler, .user_ctx = NULL};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &cors_preflight_uri));
    httpd_uri_t ota_uri = {.uri = "/api/ota", .method = HTTP_POST, .handler = ota_upload_handler, .user_ctx = NULL};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ota_uri));
    httpd_uri_t ws_uri = {.uri = "/ws", .method = HTTP_GET, .handler = ws_handler, .user_ctx = NULL, .is_websocket = true, .handle_ws_control_frames = true};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &ws_uri));
    httpd_uri_t any = {.uri = "/*", .method = HTTP_GET, .handler = redirect_handler, .user_ctx = NULL};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &any));
    httpd_uri_t any_head = {.uri = "/*", .method = HTTP_HEAD, .handler = redirect_handler, .user_ctx = NULL};
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &any_head));
}


void http_server_stop(void)
{
    if (ws_frame_process_task_handle) {
        task_manager_delete_task_by_handle(ws_frame_process_task_handle);
        ws_frame_process_task_handle = NULL;
    }
    if (ws_frame_queue) { vQueueDelete(ws_frame_queue); ws_frame_queue = NULL; }
    if (server) { httpd_stop(server); server = NULL; }
}

httpd_handle_t get_web_server_handle(void) { return server; }
