#pragma once
#include <stdint.h>

#define MAC_ADDR_LEN 6
#define NUM 3

struct radiotap_hdr
{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
};

struct beacon_hdr
{
    uint8_t bc_frame;
    uint8_t bc_ctrF;
    uint16_t bc_dur;
    uint8_t bc_dest_addr[MAC_ADDR_LEN];
    uint8_t bc_src_addr[MAC_ADDR_LEN];
    uint8_t bc_BSSID[MAC_ADDR_LEN];
    uint16_t bc_num;
};

struct wireless_hdr
{
    uint32_t fixed[NUM];
    uint8_t tag_num;
    uint8_t tag_len;
};