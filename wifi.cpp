/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sstream>
#include <memory>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/cyw43_arch.h"
#include "hardware/rtc.h"
#include "pico/util/datetime.h"
#include "hardware/watchdog.h"
#include "hardware/flash.h"
#include "hardware/sync.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "server_config.h"

#include <functional>
#include <algorithm>
#include <climits>
#include <vector>
#include <random>
#include <time.h>
#include <memory>
#include <ctime>

#include "json.hpp"
using json = nlohmann::json;

#define TCP_PORT 4242
#define DEBUG_printf printf
#define BUF_SIZE 2048
#define TEST_ITERATIONS 10
#define POLL_TIME_S 5



typedef struct TCP_CLIENT_T_ {
  uint8_t buffer_sent[TCP_SERVER_BUF_SIZE];
  uint8_t buffer_recv[TCP_SERVER_BUF_SIZE];
  u_int64_t last_packet_tt = 0;
  u_int64_t last_ping = 0;
  struct tcp_pcb *client_pcb;
  int packet_len = -1;
  int data_len = 0;
  int recv_len;
} TCP_CLIENT_T;

typedef struct TCP_SERVER_T_ {
  std::pair<std::string, std::shared_ptr<TCP_CLIENT_T>> clients[TCP_SERVER_MAX_CLIENTS];
  struct tcp_pcb *server_pcb;
  bool opened;
} TCP_SERVER_T;

enum class PACKET_TYPE {
  PING,
  INFO,
  SET,
  GET,

  ERROR,

  UNKNOWN
};

static std::string get_tcp_client_id(struct tcp_pcb *client);
static int index_of_tcp_client(TCP_SERVER_T *state, const std::string &id);
static err_t tcp_close_client(struct tcp_pcb *tpcb);
u_int64_t get_datetime_ms();

#define FLASH_RUID_DATA_BYTES 8

uint8_t __flash_uid[FLASH_RUID_DATA_BYTES];
char __flash_uid_s[FLASH_RUID_DATA_BYTES * 2] = "";

void read_chip_uid() {
  uint32_t interrupts = save_and_disable_interrupts();
  flash_get_unique_id(__flash_uid);
  restore_interrupts(interrupts);
  sprintf(__flash_uid_s, "%02X%02X%02X%02X%02X%02X%02X%02X", __flash_uid[0], __flash_uid[1], __flash_uid[2], __flash_uid[3], __flash_uid[4], __flash_uid[5], __flash_uid[6], __flash_uid[7]);
}

std::string PACKET_TYPES(const PACKET_TYPE& command) {
  switch (command) {
    case PACKET_TYPE::SET:
      return "SET";
    case PACKET_TYPE::GET:
      return "GET";
    case PACKET_TYPE::PING:
      return "PING";
    case PACKET_TYPE::INFO:
      return "INFO";
    case PACKET_TYPE::ERROR:
      return "ERROR";
    default:
      return "";
  }
}

// The ERROR packet can't be received by the server, but it can be sent by the server to the client.
PACKET_TYPE packet_type_from_string(const std::string& value) {
  if (value == "SET") {
    return PACKET_TYPE::SET;
  }

  if (value == "GET") {
    return PACKET_TYPE::GET;
  }

  if (value == "PING") {
    return PACKET_TYPE::PING;
  }

  if (value == "INFO") {
    return PACKET_TYPE::INFO;
  }

  return PACKET_TYPE::UNKNOWN;
}

std::string create_error_packet(const std::string &client_id, const std::string &message) {
  json packet = {
    {"type", PACKET_TYPES(PACKET_TYPE::ERROR)},
    {"client_id", client_id},
    {"message", message}
  };

  return packet.dump();
}

std::string parse_data_to_be_sent(const std::string &data, const std::string &client_id) {
  std::string data_to_be_sent = data;

#ifdef AES_ENCRYPTION_KEY
  printf("[Sender] Encrypting packet for %s, Raw Packet:\n", client_id.c_str());
  printf("%s\n", data.c_str());
  data_to_be_sent = encrypt_256_aes_ctr(data);
#endif

  if (data_to_be_sent == "") {
    return "";
  }

  int data_length = data_to_be_sent.size();
  printf("[Sender] Data length: %d\n", data_length);
  return std::to_string(data_length) + std::string(";") + data_to_be_sent;
}

err_t tcp_server_send_data(void *arg, struct tcp_pcb *tpcb, const std::string &data) {
  const std::string client_id = get_tcp_client_id(tpcb);
  const std::string data_to_be_sent = parse_data_to_be_sent(data, client_id);
  if (data_to_be_sent == "") {
    return ERR_VAL;
  }

  if (data_to_be_sent.size() > TCP_SERVER_BUF_SIZE) {
    printf("[Sender] Data too large to send\n");
    return ERR_VAL;
  }

  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);

  const int client_index = index_of_tcp_client(state, client_id);

  if (client_index == -1) {
    printf("[Sender] Client %s not found\n", client_id.c_str());
    tcp_close_client(tpcb);
    return ERR_VAL;
  }

  std::shared_ptr<TCP_CLIENT_T> client = (state->clients[client_index]).second;

  std::fill_n(client->buffer_sent, TCP_SERVER_BUF_SIZE, 0);

  for(int i = 0; i < data_to_be_sent.size(); i++) {
    client->buffer_sent[i] = (uint8_t)data_to_be_sent[i];
  }

  client->buffer_sent[data_to_be_sent.size()] = (uint8_t)'\0';

  printf("[Sender] Writing %ld bytes to client (%s)\n", data_to_be_sent.size(), client_id.c_str());

  cyw43_arch_lwip_check();
  err_t err = tcp_write(tpcb, client->buffer_sent, data_to_be_sent.size(), TCP_WRITE_FLAG_COPY);

  if (err != ERR_OK) {
    printf("[Sender] Failed to write data %d (%s)\n", err, client_id.c_str());
    return err;
  }

  return ERR_OK;
}

void send_to_all_tcp_clients(TCP_SERVER_T *state, const std::string &data) {
  cyw43_arch_lwip_begin();
  for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
    if (state->clients[i].first != "") {
      //try {
        tcp_server_send_data(state, state->clients[i].second->client_pcb, data);
      //} //catch (...) { }
    }
  }
  cyw43_arch_lwip_end();
}

uint32_t __data_last_sent_to_all_clients = 0;
json __data_to_send_to_all_clients = {};
bool __send_data_to_all_clients = false;

void send_get_packet_to_all(const json &data) {
  __data_to_send_to_all_clients = data;
  __send_data_to_all_clients = true;
}

void sender_main_loop(TCP_SERVER_T *tcp_server_state) {
  if (__send_data_to_all_clients) {
    const uint32_t now = to_ms_since_boot(get_absolute_time());

    // Add a timeout to prevent spamming
    if (now - __data_last_sent_to_all_clients > 1000) {
      __data_last_sent_to_all_clients = now;
      __send_data_to_all_clients = false;

      json packet = {
        {"type", PACKET_TYPES(PACKET_TYPE::GET)},
        {"client_id", "server"},
        {"data", __data_to_send_to_all_clients}
      };

      send_to_all_tcp_clients(tcp_server_state, packet.dump());
    }
  }
}

void handle_client_response(void *arg, struct tcp_pcb *tpcb, const std::string &data) {
  const std::string client_id = get_tcp_client_id(tpcb);

  //try {
    json parsed_data = json::parse(data);
    if (!parsed_data.contains("type")) {
      printf("[Handler] Client %s sent invalid data: %s\n", client_id.c_str(), data.c_str());
      return;
    }

    TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
    const int client_index = index_of_tcp_client(state, client_id);

    if (!parsed_data["type"].is_string()) {
      printf("[Handler] Client %s sent invalid data: %s\n", client_id.c_str(), data.c_str());
      return;
    }

    const std::string s_type = parsed_data["type"].get<std::string>();
    const PACKET_TYPE type = packet_type_from_string(s_type);

    if (type == PACKET_TYPE::UNKNOWN) {
      printf("[Handler] Client %s sent invalid data: %s\n", client_id.c_str(), data.c_str());
      return;
    }

    const u_int64_t now = get_datetime_ms();
    (state->clients[client_index]).second->last_ping = now;

    std::string packet_id = "";
    if (parsed_data.contains("id") && parsed_data["id"].is_string()) {
      packet_id = parsed_data["id"].get<std::string>();
    }

    json packet = {
      {"id", packet_id},
      {"client_id", client_id},
      {"type", s_type}
    };

    switch (type) {
      case PACKET_TYPE::PING: {
        tcp_server_send_data(arg, tpcb, packet.dump());
        return;
      }
      case PACKET_TYPE::INFO: {
        printf("[Handler] Sending INFO Packet to %s\n", client_id.c_str());
        char country_code[2] = {COUNTRY_CODE_0, COUNTRY_CODE_1};
        packet["data"] = {
          {"watchdog_enable_reboot", watchdog_enable_caused_reboot()},
          {"uptime", to_ms_since_boot(get_absolute_time()) / 1000},
          {"country_code", std::string(country_code, 2)},
          {"watchdog_reboot", watchdog_caused_reboot()},
          {"firmware_version", FIRMWARE_VERSION},
          {"serial_number", __flash_uid_s},
          {"type", SERVICE_TYPE},
          {"ssid", WIFI_SSID}
        };
        printf("[Handler] INFO Packet prepared for %s\n", client_id.c_str());
        tcp_server_send_data(arg, tpcb, packet.dump());
        printf("[Handler] INFO Packet sent to %s\n", client_id.c_str());
        return;
      }
      default:
        break;
    }

    json body = {};
    if (parsed_data.contains("body")) {
      body = parsed_data["body"];
    }

    //packet["data"] = service_handle_packet(body, type);
    tcp_server_send_data(arg, tpcb, packet.dump());
//   } catch (...) {
//     printf("[Handler] Failed to parse data from %s\n", client_id.c_str());

//     try {
//       tcp_server_send_data(arg, tpcb, create_error_packet(client_id, "Failed to parse data"));
//     } catch (...) {}
//   }
}

static std::string get_tcp_client_id(struct tcp_pcb *client) {
  return std::string(ip4addr_ntoa(&client->remote_ip)) + ":" + std::to_string(client->remote_port);
}

static int index_of_tcp_client(TCP_SERVER_T *state, const std::string &id) {
  for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
    if (state->clients[i].first == id) {
      return i;
    }
  }

  return -1;
}

u_int64_t get_datetime_ms() {
  std::tm epoch_start;
  epoch_start.tm_sec = 0;
  epoch_start.tm_min = 0;
  epoch_start.tm_hour = 0;
  epoch_start.tm_mday = 1;
  epoch_start.tm_mon = 0;
  epoch_start.tm_year = 1970 - 1900;

  std::time_t basetime = std::mktime(&epoch_start);

  datetime_t dt;
  rtc_get_datetime(&dt);

  std::tm now = {};
  now.tm_year = dt.year - 1900;
  now.tm_mon = dt.month - 1;
  now.tm_mday = dt.day;
  now.tm_hour = dt.hour;
  now.tm_min = dt.min;
  now.tm_sec = dt.sec;

  const u_int64_t ms = std::difftime(std::mktime(&now), basetime);
  return ms * 1000;
}

static err_t tcp_close_client(struct tcp_pcb *tpcb) {
  err_t err = ERR_OK;

  if (tpcb == NULL) {
    return err;
  }

  printf("[Server] Closing connection for %s\n", get_tcp_client_id(tpcb).c_str());

  tcp_arg(tpcb, NULL);
  tcp_poll(tpcb, NULL, 0);
  tcp_sent(tpcb, NULL);
  tcp_recv(tpcb, NULL);
  tcp_err(tpcb, NULL);
  err = tcp_close(tpcb);

  if (err != ERR_OK) {
    printf("[Server] Close failed %d, calling abort\n", err);
    tcp_abort(tpcb);
    err = ERR_ABRT;
  }

  return err;
}

static TCP_SERVER_T* tcp_server_init(void) {
  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(calloc(1, sizeof(TCP_SERVER_T)));

  if (!state) {
    printf("[Server] Failed to allocate state\n");
    return NULL;
  }

  return state;
}

static int first_empty_client_slot(TCP_SERVER_T *state) {
  for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
    if (state->clients[i].first == "") {
      return i;
    }
  }

  return -1;
}

static err_t tcp_close_client_by_index(TCP_SERVER_T *state, const int &index) {
  const err_t err = tcp_close_client(state->clients[index].second->client_pcb);
  state->clients[index].second.reset();
  state->clients[index].first = "";

  return err;
}

static void close_all_tcp_clients(TCP_SERVER_T *state) {
  for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
    if (state->clients[i].first != "") {
      tcp_close_client_by_index(state, i);
    }
  }
}

static err_t tcp_server_close(void *arg) {
  printf("[Server] Closing the server\n");

  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
  state->opened = false;
  close_all_tcp_clients(state);

  if (state->server_pcb) {
    tcp_arg(state->server_pcb, NULL);
    tcp_close(state->server_pcb);
    state->server_pcb = NULL;
  }

  return ERR_OK;
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
  printf("[Server] %u bytes sent to client %s\n", len, get_tcp_client_id(tpcb).c_str());
  return ERR_OK;
}

err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  //try {
    TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
    const std::string client_id = get_tcp_client_id(tpcb);

    if (err != 0) {
      printf("[Server] Receiver error %d (%s)\n", err, client_id.c_str());
    }

    const int client_index = index_of_tcp_client(state, client_id);

    if (client_index == -1) {
      printf("[Server] Client %s not found\n", client_id.c_str());
      tcp_close_client(tpcb);
      pbuf_free(p);
      return ERR_VAL;
    }

    if (!p) {
      tcp_close_client_by_index(state, client_index);
      pbuf_free(p);
      return ERR_VAL;
    }

    std::shared_ptr<TCP_CLIENT_T> client = (state->clients[client_index]).second;

    cyw43_arch_lwip_check();
    if (p->tot_len > 0) {
      const u_int64_t now = get_datetime_ms();
      if (now - client->last_packet_tt > 1500) {
        client->packet_len = -1;
      }

      client->last_packet_tt = now;

      if (client->packet_len == -1) {
        client->recv_len = 0;
      }

      printf("[Server] Received %d bytes (%d are from previous packets) from (%s)\n", p->tot_len, client->recv_len, client_id.c_str());

      const uint16_t buffer_left = TCP_SERVER_BUF_SIZE - client->recv_len;
      client->recv_len += pbuf_copy_partial(
        p, client->buffer_recv + client->recv_len,
        p->tot_len > buffer_left ? buffer_left : p->tot_len, 0\
      );

      tcp_recved(tpcb, p->tot_len);
    }

    if (client->packet_len == -1) {
      std::string partial_packet((char*)client->buffer_recv, client->recv_len);
      std::string packet_length_s;

      std::istringstream iss_input(partial_packet);
      std::getline(iss_input, packet_length_s, ';');

      if (packet_length_s != partial_packet) {
        int packet_length = std::stoi(packet_length_s);
        if (packet_length > 0) {
          client->packet_len = packet_length + packet_length_s.size() + 1;
          client->data_len = packet_length_s.size() + 1;
        }
      }
    }
    
    if (client->recv_len >= client->packet_len) {
      std::string packet((char*)client->buffer_recv, client->data_len, client->packet_len - client->data_len);

#ifdef AES_ENCRYPTION_KEY
      printf("[Server] Decrypting packet from %s\n", client_id.c_str());
      packet = decrypt_256_aes_ctr(packet);
      printf("[Server] Packet decrypted from %s (%s)\n", client_id.c_str(), packet.c_str());
#endif

      if (packet != "") {
        handle_client_response(arg, tpcb, packet);
      }

      client->packet_len = -1;
      client->recv_len = 0;
    }

    pbuf_free(p);
    return ERR_OK;
//   } catch (const std::exception &e) {
//     printf("[Server] Exception: %s\n", e.what());
//     pbuf_free(p);
//     return ERR_VAL;
//   }
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb) {
  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
  const std::string client_id = get_tcp_client_id(tpcb);
  const int client_index = index_of_tcp_client(state, client_id);

 // try {
    std::shared_ptr<TCP_CLIENT_T> client = (state->clients[client_index]).second;
    const u_int64_t now = get_datetime_ms();
    const u_int64_t diff = (now - client->last_ping) / 1000;
    if (diff > TCP_SERVER_INACTIVE_TIME_S) {
      printf("[Server] Client %s is inactive for %s seconds\n", client_id.c_str(), std::to_string(diff).c_str());
      tcp_close_client_by_index(state, client_index);
    }
//   } catch (...) {
//     printf("[Server] Poll error for %s\n", client_id.c_str());
//     tcp_close_client_by_index(state, client_index);
//   }

  return ERR_OK;
}

static void tcp_server_err(void *arg, err_t err) {
  if (err != ERR_ABRT) {
    printf("[Server] Client thrown error (%d)\n", err);
  } else {
    printf("[Server] Client aborted error\n");
  }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);

 // try {
    if (err != ERR_OK || client_pcb == NULL) {
      printf("[Server] Failure in accept\n");
      return ERR_VAL;
    }

    const std::string client_id = get_tcp_client_id(client_pcb);

    if (index_of_tcp_client(state, client_id) >= 0) {
      printf("[Server] Client already connected (%s)\n", client_id.c_str());
      return ERR_OK;
    }

    const int empty_index = first_empty_client_slot(state);
    if (empty_index < 0) {
      printf("[Server] No empty client slot\n");
      tcp_close_client(client_pcb);
      return ERR_ABRT;
    }

    printf("[Server] Client connected (%s) on (%d)\n", client_id.c_str(), empty_index);

    std::shared_ptr<TCP_CLIENT_T> client = std::make_shared<TCP_CLIENT_T>();
    state->clients[empty_index] = std::make_pair(client_id, client);

    const u_int64_t now = get_datetime_ms();

    client->client_pcb = client_pcb;
    client->last_ping = now;
    tcp_arg(client_pcb, state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_poll(client_pcb, tcp_server_poll, TCP_SERVER_POLL_TIME_S * 2);
    tcp_err(client_pcb, tcp_server_err);

    return ERR_OK;
//   } catch (...) {
//     const std::string client_id = get_tcp_client_id(client_pcb);
//     printf("[Server] Exception in accept (%s)\n", client_id.c_str());

//     tcp_close_client_by_index(state, index_of_tcp_client(state, client_id));
//     return ERR_ABRT;
//   }
}

static bool tcp_server_open(void *arg) {
  TCP_SERVER_T *state = static_cast<TCP_SERVER_T*>(arg);
  printf("[Server] Starting (%s:%u)\n", ip4addr_ntoa(netif_ip4_addr(netif_list)), TCP_SERVER_PORT);

  struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!pcb) {
    printf("[Server] Failed to create pcb\n");
    return false;
  }

  err_t err = tcp_bind(pcb, NULL, TCP_SERVER_PORT);
  if (err) {
    printf("[Server] Failed to bind to port %d\n");
    return false;
  }

  state->server_pcb = tcp_listen_with_backlog(pcb, 1);
  if (!state->server_pcb) {
    printf("[Server] Failed to listen\n");
    if (pcb) {
      tcp_close(pcb);
    }

    return false;
  }

  printf("[Server] Successfully started\n");
  state->opened = true;

  tcp_arg(state->server_pcb, state);
  tcp_accept(state->server_pcb, tcp_server_accept);

  return true;
}

uint32_t last_wifi_check = 0;

void start_tcp_server_module() {
  TCP_SERVER_T *tcp_server_state = tcp_server_init();
  if (!tcp_server_state) {
    return;
  }

  if (!tcp_server_open(tcp_server_state)) {
    return;
  }

  while(tcp_server_state->opened) {
    sender_main_loop(tcp_server_state);

    const uint32_t now = to_ms_since_boot(get_absolute_time());

    if (now - last_wifi_check > 10000) {
      last_wifi_check = now;

      const int status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
      switch(status) {
        case CYW43_LINK_DOWN:
        case CYW43_LINK_FAIL:
        case CYW43_LINK_NONET:
          printf("[Wifi-Check] WiFi down\n");
          cyw43_arch_wifi_connect_async(WIFI_SSID, WIFI_PASSWORD, WIFI_AUTH);
          break;
        case CYW43_LINK_BADAUTH:
          printf("[Wifi-Check] WiFi bad auth\n");
          break;
        case CYW43_LINK_JOIN:
          printf("[Wifi-Check] WiFi join\n");
          break;
        case CYW43_LINK_NOIP:
          printf("[Wifi-Check] WiFi no IP\n");
          break;
      }
    }

#if PICO_CYW43_ARCH_POLL
    cyw43_arch_poll();
    sleep_ms(1);
#else
    tight_loop_contents();
#endif
  }

  printf("[Server] Closed\n");
  free(tcp_server_state);
}

// typedef struct TCP_SERVER_T_ {
//     struct tcp_pcb *server_pcb;
//     struct tcp_pcb *client_pcb;
//     bool complete;
//     uint8_t buffer_sent[BUF_SIZE];
//     uint8_t buffer_recv[BUF_SIZE];
//     int sent_len;
//     int recv_len;
//     int run_count;
// } TCP_SERVER_T;

// static TCP_SERVER_T* tcp_server_init(void) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)calloc(1, sizeof(TCP_SERVER_T));
//     if (!state) {
//         DEBUG_printf("failed to allocate state\n");
//         return NULL;
//     }
//     return state;
// }

// static err_t tcp_server_close(void *arg) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     err_t err = ERR_OK;
//     if (state->client_pcb != NULL) {
//         tcp_arg(state->client_pcb, NULL);
//         tcp_poll(state->client_pcb, NULL, 0);
//         tcp_sent(state->client_pcb, NULL);
//         tcp_recv(state->client_pcb, NULL);
//         tcp_err(state->client_pcb, NULL);
//         err = tcp_close(state->client_pcb);
//         if (err != ERR_OK) {
//             DEBUG_printf("close failed %d, calling abort\n", err);
//             tcp_abort(state->client_pcb);
//             err = ERR_ABRT;
//         }
//         state->client_pcb = NULL;
//     }
//     if (state->server_pcb) {
//         tcp_arg(state->server_pcb, NULL);
//         tcp_close(state->server_pcb);
//         state->server_pcb = NULL;
//     }
//     return err;
// }

// static err_t tcp_server_result(void *arg, int status) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     if (status == 0) {
//         DEBUG_printf("test success\n");
//     } else {
//         DEBUG_printf("test failed %d\n", status);
//     }
//     state->complete = true;
//     return 0;//tcp_server_close(arg);
// }

// static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     DEBUG_printf("tcp_server_sent %u\n", len);
//     state->sent_len += len;

//     if (state->sent_len >= BUF_SIZE) {

//         // We should get the data back from the client
//         state->recv_len = 0;
//         DEBUG_printf("Waiting for buffer from client\n");
//     }

//     return ERR_OK;
// }

// err_t tcp_server_send_data(void *arg, struct tcp_pcb *tpcb)
// {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     for(int i=0; i< BUF_SIZE; i++) {
//         state->buffer_sent[i] = rand();
//     }

//     state->sent_len = 0;
//     DEBUG_printf("Writing %ld bytes to client\n", BUF_SIZE);
//     // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
//     // can use this method to cause an assertion in debug mode, if this method is called when
//     // cyw43_arch_lwip_begin IS needed
//     cyw43_arch_lwip_check();
//     err_t err = tcp_write(tpcb, state->buffer_sent, BUF_SIZE, TCP_WRITE_FLAG_COPY);
//     if (err != ERR_OK) {
//         DEBUG_printf("Failed to write data %d\n", err);
//         return tcp_server_result(arg, -1);
//     }
//     return ERR_OK;
// }

// err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     if (!p) {
//         return tcp_server_result(arg, -1);
//     }
//     // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
//     // can use this method to cause an assertion in debug mode, if this method is called when
//     // cyw43_arch_lwip_begin IS needed
//     cyw43_arch_lwip_check();
//     if (p->tot_len > 0) {
//         DEBUG_printf("tcp_server_recv %d/%d err %d\n", p->tot_len, state->recv_len, err);

//         // Receive the buffer
//         const uint16_t buffer_left = BUF_SIZE - state->recv_len;
//         state->recv_len += pbuf_copy_partial(p, state->buffer_recv + state->recv_len,
//                                              p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
//         tcp_recved(tpcb, p->tot_len);
//     }
//     pbuf_free(p);

//     // Have we have received the whole buffer
//     if (state->recv_len == BUF_SIZE) {

//         // check it matches
//         if (memcmp(state->buffer_sent, state->buffer_recv, BUF_SIZE) != 0) {
//             DEBUG_printf("buffer mismatch\n");
//             return tcp_server_result(arg, -1);
//         }
//         DEBUG_printf("tcp_server_recv buffer ok\n");

//         // Test complete?
//         state->run_count++;
//         if (state->run_count >= TEST_ITERATIONS) {
//             tcp_server_result(arg, 0);
//             return ERR_OK;
//         }

//         // Send another buffer
//         return tcp_server_send_data(arg, state->client_pcb);
//     }
//     return ERR_OK;
// }

// static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb) {
//     DEBUG_printf("tcp_server_poll_fn\n");
//     return tcp_server_result(arg, -1); // no response is an error?
// }

// static void tcp_server_err(void *arg, err_t err) {
//     if (err != ERR_ABRT) {
//         DEBUG_printf("tcp_client_err_fn %d\n", err);
//         tcp_server_result(arg, err);
//     }
// }

// static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     if (err != ERR_OK || client_pcb == NULL) {
//         DEBUG_printf("Failure in accept\n");
//         tcp_server_result(arg, err);
//         return ERR_VAL;
//     }
//     DEBUG_printf("Client connected\n");

//     state->client_pcb = client_pcb;
//     tcp_arg(client_pcb, state);
//     tcp_sent(client_pcb, tcp_server_sent);
//     tcp_recv(client_pcb, tcp_server_recv);
//     tcp_poll(client_pcb, tcp_server_poll, 10);
//     tcp_err(client_pcb, tcp_server_err);

//     return tcp_server_send_data(arg, state->client_pcb);
// }

// static bool tcp_server_open(void *arg) {
//     TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
//     DEBUG_printf("Starting server at %s on port %u\n", ip4addr_ntoa(netif_ip4_addr(netif_list)), TCP_PORT);

//     struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
//     if (!pcb) {
//         DEBUG_printf("failed to create pcb\n");
//         return false;
//     }

//     err_t err = tcp_bind(pcb, NULL, TCP_PORT);
//     if (err) {
//         DEBUG_printf("failed to bind to port %u\n", TCP_PORT);
//         return false;
//     }

//     state->server_pcb = tcp_listen_with_backlog(pcb, 1);
//     if (!state->server_pcb) {
//         DEBUG_printf("failed to listen\n");
//         if (pcb) {
//             tcp_close(pcb);
//         }
//         return false;
//     }

//     tcp_arg(state->server_pcb, state);
//     tcp_accept(state->server_pcb, tcp_server_accept);

//     return true;
// }

// void run_tcp_server_test(void) {
//     TCP_SERVER_T *state = tcp_server_init();
//     if (!state) {
//         return;
//     }
//     if (!tcp_server_open(state)) {
//         tcp_server_result(state, -1);
//         return;
//     }
//     while(!state->complete) {
//         // the following #ifdef is only here so this same example can be used in multiple modes;
//         // you do not need it in your code
// #if PICO_CYW43_ARCH_POLL
//         // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
//         // main loop (not from a timer) to check for Wi-Fi driver or lwIP work that needs to be done.
//         cyw43_arch_poll();
//         // you can poll as often as you like, however if you have nothing else to do you can
//         // choose to sleep until either a specified time, or cyw43_arch_poll() has work to do:
//         cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
// #else
//         // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
//         // is done via interrupt in the background. This sleep is just an example of some (blocking)
//         // work you might be doing.
//         sleep_ms(1000);
// #endif
//     }
//     free(state);
// }

void startWifi() {
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return;
    }

    cyw43_arch_enable_sta_mode();

    printf("Connecting to Wi-Fi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms("NETGEAR84", "cloudywindow678", CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect.\n");
        return;
    } else {
        printf("Connected.\n");
    }

    
    start_tcp_server_module();

    while(1)
    {
        tight_loop_contents();
    }

    //run_tcp_server_test();
    //cyw43_arch_deinit();
}