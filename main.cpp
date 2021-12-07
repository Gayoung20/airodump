#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <map>
#include <iostream>

#include "BeaconHdr.h"
#include "mac.h"

using namespace std;

void usage();
bool parsing(char *pkt);

map<Mac, int> beacon_table;
map<Mac, string> essid_table; 

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        char *pkt = (char *)malloc(header->caplen);
        pkt = (char *)packet;
        map<Mac, int>::iterator itr;

        if (parsing(pkt))
        {
            for (itr = beacon_table.begin(); itr != beacon_table.end(); itr++)
            {
                printf("BSSID: %s\n", std::string(itr->first).data());
                printf("beacon: %d\n", itr->second);
                printf("ESSID: ");
                cout << essid_table[itr->first] << endl;
                printf("------------------------------------------------------------\n");
            }
        }
        else
        {
            printf("it's not Beacon frame\n");
            printf("------------------------------------------------------------\n");
        }
    }

    pcap_close(handle);
    return 0;
}

void usage()
{
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0");
}

bool parsing(char *pkt) {
    int location = 0;

    struct radiotap_hdr *radiotap;
    radiotap = (struct radiotap_hdr *)pkt;
    location += radiotap->it_len;
    struct beacon_hdr *beaconHdr;
    beaconHdr = (struct beacon_hdr *)(pkt+location);
    location += sizeof(beacon_hdr);
    struct wireless_hdr *wireless;
    wireless = (struct wireless_hdr *)(pkt+location);

    if(beaconHdr->bc_frame != 0x80) {
        return false;
    }

    Mac bssid;
    bssid = Mac(beaconHdr->bc_BSSID);

    if(beacon_table.find(bssid) != beacon_table.end()) {
        beacon_table[bssid]++;
    } else {
        beacon_table.insert(make_pair(bssid, 1));
    }

    location += sizeof(wireless_hdr) - 2;

    int len = wireless->tag_len;
    char *str = (char *)malloc(sizeof(char) * len);
    memcpy(str, pkt+location, len);
    string essid(str, len);
    
    if(essid_table.find(bssid) == essid_table.end()) {
        essid_table.insert(make_pair(bssid, essid));
    }

    free(str);
    return true;

}