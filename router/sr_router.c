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
#include <stdlib.h>
#include <string.h>

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

  print_addr_eth(packet);
  uint8_t *packet_cpy = malloc(len);
  memcpy(packet_cpy, packet, len);
  
  sr_ethernet_hdr_t eth_hdr;
  memcpy(&eth_hdr, packet_cpy, 14);

  if(ethertype((uint8_t *)&eth_hdr) == ethertype_arp)
  {
    sr_arp_hdr_t arp_hdr;
    memcpy(&arp_hdr, packet_cpy + 14, len - 14);
    print_hdr_arp((uint8_t *)&arp_hdr);

    if(arp_hdr.ar_op == htons(arp_op_request))
    {
      printf("received arp req\n");
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

            arp_hdr.ar_op = htons(arp_op_reply);
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
    else if(arp_hdr.ar_op == htons(arp_op_reply))
    {
      struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, arp_hdr.ar_sip);

      if(ae != NULL)
      {
        printf("arp mapping already exists \n");
        return;
      }
      else
      {
        struct sr_if* if_walker = 0;

        if(sr->if_list == 0)
        {
            printf(" Interface list empty \n");
            return;
        }

        if_walker = sr->if_list;
        
        while(if_walker->next)
        {
          if(arp_hdr.ar_tip == if_walker->ip)
          {
            printf("adding new mapping\n");
            sr_arpcache_insert(&sr->cache, arp_hdr.ar_sha, arp_hdr.ar_sip);
            return;
          }
          if_walker = if_walker->next;
        }

        /*find the arpreq with the ip matching and sent all pkts and destroy*/
        struct sr_arpreq *arpreq_walker = sr->cache.requests;

        while(arpreq_walker != NULL)
        {
          if(arp_hdr.ar_sip == arpreq_walker->ip)
            break;
        }
        if(arpreq_walker != NULL)
        {
          while(arpreq_walker->packets != NULL)
          {
            sr_send_packet(sr, arpreq_walker->packets->buf, arpreq_walker->packets->len, arpreq_walker->packets->iface);
            arpreq_walker->packets = arpreq_walker->packets->next;
          }
          sr_arpreq_destroy(&sr->cache, arpreq_walker);
        }
      }
    }    
  }

  else if(ethertype((uint8_t *)&eth_hdr) == ethertype_ip)
  {
    printf("received arp req\n");
    sr_ip_hdr_t ip_hdr;
    uint16_t ip_checksum = 0;

    memcpy(&ip_hdr, packet_cpy + 14, 20);
    ip_checksum = cksum(&ip_hdr, 20);
    if(ip_checksum != 0xffff)
    {
      printf("wrong checksum\n");
      return;
    }

    ip_hdr.ip_ttl--;
    ip_hdr.ip_sum = 0;
    ip_checksum = cksum(&ip_hdr, 20);
    ip_hdr.ip_sum = ip_checksum;

    printf("checksum validated\n");

    if(!ip_hdr.ip_ttl)
    {
      printf("ttl expired \n");
      memcpy(&eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
      struct sr_if *if_temp = sr_get_interface(sr, (const char *)interface);
      memcpy(&eth_hdr.ether_shost, if_temp->addr, ETHER_ADDR_LEN);

      ip_hdr.ip_dst = ip_hdr.ip_src;
      ip_hdr.ip_src = if_temp->ip;
      ip_hdr.ip_p = htons(ip_protocol_icmp);
      
      sr_icmp_hdr_t icmp_hdr;
      
      icmp_hdr.icmp_type = 11;
      icmp_hdr.icmp_code = 0;

      realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);
      memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
      memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
      memcpy(packet_cpy, &eth_hdr, 14);
      sr_send_packet(sr, packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14, interface);
    }

    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
        printf(" Interface list empty \n");

    if_walker = sr->if_list;
    
    while(if_walker->next)
    {
      if(ip_hdr.ip_dst == if_walker->ip)
      {
        print_addr_ip_int(ip_hdr.ip_dst);
        print_addr_ip_int(if_walker->ip);
        printf("port unreachable send ICMP\n");
        memcpy(&eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
        if_walker = sr_get_interface(sr, (const char *)interface);
        memcpy(&eth_hdr.ether_shost, if_walker->addr, ETHER_ADDR_LEN);
        
        ip_hdr.ip_dst = ip_hdr.ip_src;
        ip_hdr.ip_src = if_walker->ip;

        sr_icmp_hdr_t icmp_hdr;
        if(ip_hdr.ip_p == htons(ip_protocol_icmp))
        {
          printf("echo reply by the router\n");
          icmp_hdr.icmp_type = 0;
          icmp_hdr.icmp_code = 0;  
        }
        else
        {
          printf("port unreachable\n");
          icmp_hdr.icmp_type = 3;
          icmp_hdr.icmp_code = 3;
        }

        ip_hdr.ip_p = htons(ip_protocol_icmp);

        realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);
        memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
        memcpy(packet_cpy, &eth_hdr, 14);
        sr_send_packet(sr, packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14, interface);
        return;
      }
      if_walker = if_walker->next;
    }

    uint32_t next_hop_ip;
    char *dst_if;

    if(!sr_load_rt(sr, "rtable"))
    {
      struct sr_rt* rt_walker;

      for(rt_walker =sr->routing_table; rt_walker != 0; rt_walker = rt_walker->next)
      {
        printf("here1\n");
        print_addr_ip(rt_walker->dest);
        print_addr_ip_int(ip_hdr.ip_dst);
        if(ip_hdr.ip_dst == rt_walker->dest.s_addr)
        {
          printf("here2\n");
          print_addr_ip(rt_walker->gw);
          print_addr_ip_int(rt_walker->gw.s_addr);
          next_hop_ip = rt_walker->gw.s_addr;
          dst_if = rt_walker->interface;
          break;
        }
        /*do i need to implement longest prefix match?*/
      }
      if(rt_walker == 0)
      {
        printf("destination net unreachable send ICMP\n");
        memcpy(&eth_hdr.ether_dhost, eth_hdr.ether_shost, ETHER_ADDR_LEN);
        if_walker = sr_get_interface(sr, (const char *)interface);
        memcpy(&eth_hdr.ether_shost, if_walker->addr, ETHER_ADDR_LEN);

        ip_hdr.ip_dst = ip_hdr.ip_src;
        ip_hdr.ip_src = if_walker->ip;
        ip_hdr.ip_p = htons(ip_protocol_icmp);
        
        sr_icmp_hdr_t icmp_hdr;
        
        icmp_hdr.icmp_type = 3;
        icmp_hdr.icmp_code = 0;

        realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);
        memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
        memcpy(packet_cpy, &eth_hdr, 14);
        sr_send_packet(sr, packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14, interface);
        return;
      }
    }
    else
    {
      printf("failed to load rtable \n");
      return;
    }

    if_walker = sr_get_interface(sr, (const char *)interface);
    memcpy(&eth_hdr.ether_shost, if_walker->addr, 6);

    struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if(ae != NULL)
    {
      memcpy(&eth_hdr.ether_shost, eth_hdr.ether_dhost, ETHER_ADDR_LEN);
      memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
      memcpy(packet_cpy, &eth_hdr, 14);
      sr_send_packet(sr, packet_cpy, len, dst_if);
      free(ae);

    }
    else
    {
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet_cpy, len, dst_if);
      sr_arpreq_handle(sr, arp_req);
    }

    /*
    search routing table and get next hop ip

    lookup arp table for the mac addr for that ip

    deliver packet with that mac addr and ip
    */

  }
  /* fill in code here */

}/* end sr_ForwardPacket */

