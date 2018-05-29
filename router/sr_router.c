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

  uint8_t *packet_cpy = malloc(len);
  memcpy(packet_cpy, packet, len);
  
  sr_ethernet_hdr_t eth_hdr;
  memcpy(&eth_hdr, packet_cpy, 14);

  if(ethertype((uint8_t *)&eth_hdr) == ethertype_arp)
  {
    sr_arp_hdr_t arp_hdr;
    memcpy(&arp_hdr, packet_cpy + 14, len - 14);
    

    if(arp_hdr.ar_op == htons(arp_op_request))
    {
      printf("received arp req\n");
      struct sr_if* if_walker = 0;

      if(sr->if_list == 0)
          printf(" Interface list empty \n");

      if_walker = sr->if_list;
      
      while(if_walker)
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
      printf("received arp reply\n");
      struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, arp_hdr.ar_sip);

      if(ae != NULL)
      {
        printf("arp mapping already exists \n");
        return;
      }
      else
      {
        struct sr_if* if_walker = 0;
        struct sr_arpreq *arpreq_walker;


        if(sr->if_list == 0)
        {
            printf(" Interface list empty \n");
            return;
        }

        if_walker = sr->if_list;
        
        while(if_walker)
        {
          if(arp_hdr.ar_tip == if_walker->ip)
          {
            printf("adding new mapping\n");
            arpreq_walker = sr_arpcache_insert(&sr->cache, arp_hdr.ar_sha, arp_hdr.ar_sip);
            break;
          }
          if_walker = if_walker->next;
        }

        /*find the arpreq with the ip matching and sent all pkts and destroy*/
        if(arpreq_walker != NULL)
        {
          if(arp_hdr.ar_sip != arpreq_walker->ip)
          {
            printf("arp reply's ip does not match\n");
            sr_arpreq_destroy(&sr->cache, arpreq_walker);
            return;
          }
          printf("found pending req\n");
          while(arpreq_walker->packets != NULL)
          {
            printf("handling pending packets\n");

            sr_ethernet_hdr_t eth_hdr_mod;
            memcpy(&eth_hdr_mod, arpreq_walker->packets->buf, 14);

            ae = sr_arpcache_lookup(&sr->cache, arp_hdr.ar_sip);
            memcpy(&eth_hdr_mod.ether_shost, sr_get_interface(sr, (const char *)arpreq_walker->packets->iface)->addr, ETHER_ADDR_LEN);
            memcpy(&eth_hdr_mod.ether_dhost, ae->mac, 6);

            memcpy(arpreq_walker->packets->buf, &eth_hdr_mod, 14);

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
    sr_ip_hdr_t ip_hdr;
    memcpy(&ip_hdr, packet_cpy + 14, 20);

    if(cksum(&ip_hdr, 20) != 0xffff)
    {
      printf("wrong checksum\n");
      return;
    }
    printf("checksum validated\n");

    ip_hdr.ip_ttl--;

    if(ip_hdr.ip_ttl == 0)
    {
      printf("ttl expired \n");
      struct sr_if *if_temp = sr_get_interface(sr, (const char *)interface);

      ip_hdr.ip_dst = ip_hdr.ip_src;
      ip_hdr.ip_src = if_temp->ip;
      ip_hdr.ip_p = 1;
      
      sr_icmp_t3_hdr_t icmp_hdr;
      
      icmp_hdr.icmp_type = 11;
      icmp_hdr.icmp_code = 0;
      icmp_hdr.icmp_sum = 0;
      memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
      icmp_hdr.icmp_sum = cksum(&icmp_hdr, sizeof(icmp_hdr));

      ip_hdr.ip_len = htons(sizeof(icmp_hdr) + sizeof(ip_hdr));
      ip_hdr.ip_sum = 0;
      ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(ip_hdr));

      /*realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);*/
      memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
      memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));

      printf("checking arp cache...\n");

      struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, ip_hdr.ip_dst);
      if(ae != NULL)
      {
        printf("arp cache hit!!! \n");
        memcpy(&eth_hdr.ether_shost, if_temp->addr, ETHER_ADDR_LEN);
        memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
        memcpy(packet_cpy, &eth_hdr, 14);
        sr_send_packet(sr, packet_cpy, len, interface);
        free(ae);
      }
      else
      {
        printf("arp cache miss, queueing... \n");
        struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr.ip_dst, packet_cpy, len, interface);
        sr_arpreq_handle(sr, arp_req);
      }
      return;
    }

    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
        printf(" Interface list empty \n");
    
    if_walker = sr->if_list;

    while(if_walker)
    {
      if(ip_hdr.ip_dst == if_walker->ip)
      {
        ip_hdr.ip_dst = ip_hdr.ip_src;
        ip_hdr.ip_src = if_walker->ip;

        
        if(ip_hdr.ip_p == 1)
        {
          printf("echo reply by the router\n");
          sr_icmp_hdr_t icmp_hdr;
          icmp_hdr.icmp_type = 0;
          icmp_hdr.icmp_code = 0;
          icmp_hdr.icmp_sum = 0;
          memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
          icmp_hdr.icmp_sum = cksum(packet_cpy + sizeof(ip_hdr) + 14, len - sizeof(ip_hdr) - 14);

          ip_hdr.ip_sum = 0;
          ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(ip_hdr));

          memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
          memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
          
          printf("checking arp cache...\n");

          struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, ip_hdr.ip_dst);
          if(ae != NULL)
          {
            printf("arp cache hit!!! \n");
            memcpy(&eth_hdr.ether_shost, sr_get_interface(sr, (const char *)interface)->addr, ETHER_ADDR_LEN);
            memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
            memcpy(packet_cpy, &eth_hdr, 14);
            sr_send_packet(sr, packet_cpy, len, interface);
            free(ae);
          }
          else
          {
            printf("arp cache miss, queueing... \n");
            struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr.ip_dst, packet_cpy, len, interface);
            sr_arpreq_handle(sr, arp_req);
          }

          return;
        }
        else
        {
          printf("port unreachable send ICMP\n");
          struct sr_if *if_temp = sr_get_interface(sr, (const char *)interface);
          ip_hdr.ip_src = if_temp->ip;

          sr_icmp_t3_hdr_t icmp_hdr;
          icmp_hdr.icmp_type = 3;
          icmp_hdr.icmp_code = 3;
          icmp_hdr.icmp_sum = 0;
          memcpy(&icmp_hdr.data, packet_cpy + 14, ICMP_DATA_SIZE);
          icmp_hdr.icmp_sum = cksum(&icmp_hdr, sizeof(icmp_hdr));
          ip_hdr.ip_p = 1;

          ip_hdr.ip_len = htons(sizeof(icmp_hdr) + sizeof(ip_hdr));
          ip_hdr.ip_sum = 0;
          ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(ip_hdr));

          realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);
          memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
          memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
          
          printf("checking arp cache...\n");

          struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, ip_hdr.ip_dst);
          if(ae != NULL)
          {
            printf("arp cache hit!!! \n");
            memcpy(&eth_hdr.ether_shost, if_temp->addr, ETHER_ADDR_LEN);
            memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
            memcpy(packet_cpy, &eth_hdr, 14);
            sr_send_packet(sr, packet_cpy, len, interface);
            free(ae);
          }
          else
          {
            printf("arp cache miss, queueing... \n");
            struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr.ip_dst, packet_cpy, len, interface);
            sr_arpreq_handle(sr, arp_req);
          }
          return;
        }        
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
        printf("compare %d and %d \n", ntohl(ip_hdr.ip_dst) >> 8, ntohl(rt_walker->dest.s_addr) >> 8);
        if(ntohl(ip_hdr.ip_dst) >> 8 == ntohl(rt_walker->dest.s_addr) >> 8)
        {
          printf("here2\n");
          next_hop_ip = rt_walker->gw.s_addr;
          dst_if = rt_walker->interface;
          break;
        }
        /*do i need to implement longest prefix match?*/
      }
      if(rt_walker == 0)
      {
        printf("destination net unreachable send ICMP\n");

        struct sr_if *if_temp = sr_get_interface(sr, (const char *)interface);
        
        ip_hdr.ip_dst = ip_hdr.ip_src;
        ip_hdr.ip_src = if_temp->ip;
        ip_hdr.ip_p = 1;
        
        sr_icmp_t3_hdr_t icmp_hdr;
        
        icmp_hdr.icmp_type = 3;
        icmp_hdr.icmp_code = 0;
        icmp_hdr.icmp_sum = 0;
        memcpy(&icmp_hdr.data, packet_cpy + 14, ICMP_DATA_SIZE);
        icmp_hdr.icmp_sum = cksum(&icmp_hdr, sizeof(icmp_hdr));

        ip_hdr.ip_len = htons(sizeof(icmp_hdr) + sizeof(ip_hdr));
        ip_hdr.ip_sum = 0;
        ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(ip_hdr));

        realloc(packet_cpy, sizeof(icmp_hdr) + sizeof(ip_hdr) + 14);
        memcpy(packet_cpy + sizeof(ip_hdr) + 14, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(packet_cpy + 14, &ip_hdr, sizeof(ip_hdr));
        
        printf("checking arp cache...\n");

        struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, ip_hdr.ip_dst);
        if(ae != NULL)
        {
          printf("arp cache hit!!! \n");
          memcpy(&eth_hdr.ether_shost, sr_get_interface(sr, (const char *)interface)->addr, ETHER_ADDR_LEN);
          memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
          memcpy(packet_cpy, &eth_hdr, 14);
          sr_send_packet(sr, packet_cpy, len, interface);
          free(ae);
        }
        else
        {
          printf("arp cache miss, queueing... \n");
          struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr.ip_dst, packet_cpy, len, interface);
          sr_arpreq_handle(sr, arp_req);
        }
        return;
      }
    }
    else
    {
      printf("failed to load rtable \n");
      return;
    }

    printf("checking arp cache...\n");

    struct sr_arpentry *ae = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if(ae != NULL)
    {
      printf("arp cache hit!!! \n");
      memcpy(&eth_hdr.ether_shost, sr_get_interface(sr, (const char *)dst_if)->addr, ETHER_ADDR_LEN);
      memcpy(&eth_hdr.ether_dhost, ae->mac, 6);
      memcpy(packet_cpy, &eth_hdr, 14);
      sr_send_packet(sr, packet_cpy, len, dst_if);
      free(ae);

    }
    else
    {
      printf("arp cache miss, queueing... \n");
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet_cpy, len, dst_if);
      sr_arpreq_handle(sr, arp_req);
    }

  }
  /* fill in code here */

}/* end sr_ForwardPacket */

