/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /*
  printf("sizeof(sr_ip_hdr_t) is %d \n", sizeof(sr_ip_hdr_t));
  printf("sizeof(sr_arp_hdr_t) is %d \n", sizeof(sr_arp_hdr_t));
  printf("sizeof(sr_ethernet_hdr_t) is %d \n", sizeof(sr_ethernet_hdr_t));
  */

  uint8_t *packet_cpy = malloc(len);
  memcpy(packet_cpy, packet, len);
  
  sr_ethernet_hdr_t eth_hdr;
  memcpy(&eth_hdr, packet_cpy, 14);

  if(eth_hdr.ether_type == ethertype_arp)
  {
    sr_arp_hdr_t arp_hdr;
    memcpy(&arp_hdr, packet_cpy + 14, len - 14);

    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
        printf(" Interface list empty \n");

    if_walker = sr->if_list;
    
    while(if_walker->next)
    {
        if(arp_hdr.ar_tip == if_walker->ip)
        {
          memcpy(&eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
          if_walker = sr_get_interface(sr, (const char *)interface);
          memcpy(&eth_hdr.ether_shost, if_walker->addr, ETHER_ADDR_LEN);

          arp_hdr.ar_op = arp_op_reply;
          memcpy(arp_hdr.ar_tha, arp_hdr.ar_sha, ETHER_ADDR_LEN);
          memcpy(arp_hdr.ar_sha, if_walker->addr, ETHER_ADDR_LEN);
          arp_hdr.ar_tip = arp_hdr.ar_sip;
          arp_hdr.ar_sip = if_walker->ip;

          memcpy(packet_cpy + 14, &arp_hdr, len - 14);
          memcpy(packet_cpy, &eth_hdr, 14);
          sr_send_packet(sr, packet_cpy, len, interface);
          break;
        }
        if_walker = if_walker->next;
    }
  }

  else if(eth_hdr.ether_type == ethertype_ip)
  {
    sr_ip_hdr_t ip_hdr;
    uint16_t ip_checksum = 0;

    memcpy(ip_hdr, packet_cpy + 14, 20);
    ip_checksum = cksum(ip_hdr, 20);
    if(ip_checksum != 0xffff)
    {
      printf("wrong checksum\n");
      return;
    }

    /*
    sr_ip_hdr_t ip_hdr;
    memcpy(&ip_hdr.ip_tos, packet_cpy + 14 + 1, 1);
    memcpy(&ip_hdr.ip_len, packet_cpy + 14 + 2, 2);
    memcpy(&ip_hdr.ip_id, packet_cpy + 14 + 4, 2);
    memcpy(&ip_hdr.ip_off, packet_cpy + 14 + 6, 2);
    memcpy(&ip_hdr.ip_ttl, packet_cpy + 14 + 8, 1);
    memcpy(&ip_hdr.ip_p, packet_cpy + 14 + 9, 1);
    memcpy(&ip_hdr.ip_sum, packet_cpy + 14 + 10, 2);
    memcpy(&ip_hdr.ip_src, packet_cpy + 14 + 12, 4);
    memcpy(&ip_hdr.ip_dst, packet_cpy + 14 + 16, 4);
    */

    ip_hdr.ip_ttl--;
    ip_hdr.ip_sum = 0;
    ip_checksum = cksum(ip_hdr_buf, 20);
    ip_hdr.ip_sum = ip_checksum;

    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
        printf(" Interface list empty \n");

    if_walker = sr->if_list;
    
    while(if_walker->next)
    {
      if(ip_hdr_dst == if_walker->ip)
      {
        //dst ip is router interface respond with ICMP port unreachable
        memcpy(&eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
        if_walker = sr_get_interface(sr, (const char *)interface);
        memcpy(&eth_hdr.ether_shost, if_walker->addr, ETHER_ADDR_LEN);
        
        sr_icmp_hdr_t icmp_hdr;
        icmp_hdr.icmp_type = 3;
        icmp_hdr.icmp_code = 3;

        realloc(packet_cpy, sizeof(icmp_hdr) + 14);
        memcpy(packet_cpy + 14, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(packet_cpy, &eth_hdr, 14);
        sr_send_packet(sr, packet_cpy, sizeof(icmp_hdr) + 14, interface);
        return;
      }
      if_walker = if_walker->next;
    }

    if(!sr_load_rt(sr, "rtable"))
    {
      struct sr_rt* rt_walker;
      uint32_t next_hop_ip;

      for(rt_walker =sr->routing_table; rt_walker != 0; rt_walker = rt_walker->next)
      {
        if(ip_hdr.ip_dst == rt_walker->dest)
        {
          next_hop_ip = rt_walker->gw;
          break;
        }
        //do i need to implement longest prefix match?
      }
      if(rt_walker == 0)
        next_hop_ip = sr->routing_table->gw;
    }

    if_walker = sr_get_interface(sr, (const char *)interface);
    memcpy(&eth_hdr.ether_shost, if_walker->addr, 6);

    struct sr_arpentry *ae = sr_arpcache_lookup(sr->cache, next_hop_ip);
    if(ae != NULL)
    {
      memcpy(&eth_hdr.ether_dhost ae->mac, 6);
      free(ae);
    }
    else
    {
      struct sr_arpreq *arp_req = arpcache_queuereq(next_hop_ip, packet_cpy, len);
      sr_arpcache_sweepreqs(arp_req);
    }

    //search routing table and get next hop ip

    // lookup arp table for the mac addr for that ip

    //deliver packet with that mac addr and ip

  }
  /* fill in code here */

}/* end sr_ForwardPacket */

