/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2007 University of Washington
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Tom Henderson (tomhend@u.washington.edu)
 */
#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/lte-packet-sink.h"
#include "ns3/qos-id-seq-ts-header.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/qos-utils.h"


#include <iostream>
#include <sstream>
#include <fstream>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("LtePacketSink");
NS_OBJECT_ENSURE_REGISTERED (LtePacketSink);

TypeId 
LtePacketSink::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::LtePacketSink")
    .SetParent<Application> ()
    .AddConstructor<LtePacketSink> ()
    .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&LtePacketSink::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&LtePacketSink::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("DefaultRxSize", "The default size of packets received",
                   UintegerValue (512),
                   MakeUintegerAccessor (&LtePacketSink::m_defSize),
                   MakeUintegerChecker<uint32_t> ())        
    .AddAttribute ("FileName", "The output filename",
                   StringValue ("roundstat"),
                   MakeStringAccessor (&LtePacketSink::m_outputFilename),
                   MakeStringChecker ())   
    .AddTraceSource ("Rx", "A packet has been received",
                     MakeTraceSourceAccessor (&LtePacketSink::m_rxTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

LtePacketSink::LtePacketSink ()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_totalRx = 0;
}

LtePacketSink::~LtePacketSink()
{
  NS_LOG_FUNCTION (this);
  StatPrint();
}

uint32_t LtePacketSink::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}

Ptr<Socket>
LtePacketSink::GetListeningSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}

std::list<Ptr<Socket> >
LtePacketSink::GetAcceptedSockets (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socketList;
}

void LtePacketSink::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_socketList.clear ();

  // chain up
  Application::DoDispose ();
}


// Application Methods
void LtePacketSink::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = Socket::CreateSocket (GetNode (), m_tid);
      m_socket->Bind (m_local);
      m_socket->Listen ();
      m_socket->ShutdownSend ();
      if (addressUtils::IsMulticast (m_local))
        {
          Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
          if (udpSocket)
            {
              // equivalent to setsockopt (MCAST_JOIN_GROUP)
              udpSocket->MulticastJoinGroup (0, m_local);
            }
          else
            {
              NS_FATAL_ERROR ("Error: joining multicast on a non-UDP socket");
            }
        }
    }

  m_socket->SetRecvCallback (MakeCallback (&LtePacketSink::HandleRead, this));
  m_socket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&LtePacketSink::HandleAccept, this));
  m_socket->SetCloseCallbacks (
    MakeCallback (&LtePacketSink::HandlePeerClose, this),
    MakeCallback (&LtePacketSink::HandlePeerError, this));
}

void LtePacketSink::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  while(!m_socketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front ();
      m_socketList.pop_front ();
      acceptedSocket->Close ();
    }
  if (m_socket) 
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void LtePacketSink::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  Address from;
  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
 //     InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (from);
 //      NS_LOG_INFO("From : " << from << " Socket : " << iaddr.GetIpv4 () << " port: " << iaddr.GetPort () );

      uint16_t m_pktsize = packet->GetSize();
      m_totalRx += packet->GetSize ();
      m_rxTrace (packet, from);
      // check whether there is a previous save packet first
      Ptr<Packet> m_prevPacket = packet;
      
//==============================================================================      
//      if(packet->GetSize () == 80)
//        HandleReport(m_prevPacket,from);
//==============================================================================
      
      uint16_t m_savePktSize = 0;
      if (IsThereAnyPreviousStoredPacket(from)) {
         for(std::vector<DataWaitingPacket>::iterator it = m_waitingPacket.begin(); it != m_waitingPacket.end(); ++it) {
	    if(it->from == from) {
	          m_prevPacket = it->pkt;
	          m_savePktSize = m_prevPacket->GetSize();
	          break;
	    }
         }   
      }
      if (m_savePktSize > 0) {  // there is a previously saved packet, m_prevPacket is concatenation of previous and received
         // concatenate 
         NS_LOG_INFO("Concatenate previous stored packet and the received packet " << m_savePktSize << " " << m_pktsize );
         m_prevPacket->AddAtEnd (packet);
         m_pktsize = m_prevPacket->GetSize ();    // new pkt size from concatenation
         // delete the old record
         NS_LOG_INFO("Delete previous stored packet ! " << from << " " << m_savePktSize);
         if (m_waitingPacket.size() > 1) {
            std::vector<DataWaitingPacket> tmp (m_waitingPacket); // copy to temp
            m_waitingPacket.clear();
            
            for(std::vector<DataWaitingPacket>::iterator itw = tmp.begin() ; itw != tmp.end(); ++itw) {
	        if(itw->from != from) { // keep maintain in the waiting list
	            DataWaitingPacket keep;
	            keep.from = itw->from;
	            keep.pkt   = itw->pkt;
	            m_waitingPacket.push_back(keep);
	            NS_LOG_INFO("Keep waiting packet " << keep.from << " " << keep.pkt->GetSize() << " " << m_waitingPacket.size () );
	        }
             }
         } else m_waitingPacket.clear();
      } else m_prevPacket = packet; // there were saved packets, but none was from this address
      
      if (m_pktsize == m_defSize) {
          HandleReport(m_prevPacket,from);
      } else {
        // two cases, > and <, if higher, split them
      	if (m_pktsize > m_defSize) {
      	    uint16_t m_begin = 0;
      	    uint16_t m_length = m_defSize;
      	    while (m_pktsize >= m_defSize) {
      	        NS_LOG_INFO("Split packet : " << m_pktsize << " from : " << m_begin << " length " << m_length);
      	        Ptr<Packet> frag = m_prevPacket->CreateFragment(m_begin, m_length);
      	        HandleReport(frag, from);
      	        m_begin += (m_length);
      	        m_pktsize -= m_defSize;
      	        if (m_pktsize >= m_defSize) m_length = m_defSize;
      	        else {
      	          m_length = m_pktsize;
      	        }
      	    }
      	    if (m_pktsize > 0) {
               DataWaitingPacket tmp;
               tmp.from = from;
               tmp.pkt  = m_prevPacket->CreateFragment(m_begin, m_length);
               m_waitingPacket.push_back(tmp);
	       NS_LOG_INFO("add the rest of the packet in the waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
      	    }
      	} else {
           DataWaitingPacket tmp;
           tmp.from = from;
           tmp.pkt  = m_prevPacket;
           m_waitingPacket.push_back(tmp);
           NS_LOG_INFO("add waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
      	} // end of else m_pktsize > m_defSize
      } // end else m_pktsize == m_defSize	  
    } // end while
}


void LtePacketSink::HandleReport(Ptr<Packet> packet, Address from) 
{
 
   QosIdSeqTsHeader seqTs;
   uint32_t m_rxBytes;
   m_rxBytes = packet->GetSize (); 
   packet->PeekHeader (seqTs);
   uint8_t qosId;
   qosId = seqTs.GetQosId ();
   uint8_t privacyId;
   privacyId = seqTs.GetPrivacy ();
   uint32_t custId;
   custId = seqTs.GetCustId ();
   uint32_t opID;
   opID = seqTs.GetOpId();
   uint32_t seqNum;
   seqNum = seqTs.GetSeq ();
 
   Time now = Simulator::Now ();
   Time txtime = seqTs.GetTs ();

  
       bool lNewRecord = true;
       for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
          if(it->round == seqNum) {
            it->rxCount++;
            it->rxBytes += m_rxBytes;
            it->totDelay += (now.ToInteger (Time::US) - txtime.ToInteger (Time::US));
            it->lastRxTime = now;
            if (it->minTxTime > txtime) it->minTxTime = txtime;
            lNewRecord = false;
            break;
          }      
       }

        if (lNewRecord) {
           StatRecord tmp;
           tmp.round = seqNum;
           tmp.rxCount = 1;
           tmp.rxBytes = m_rxBytes;
           tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
           tmp.firstRxTime = now;
           tmp.lastRxTime = now;
           tmp.minTxTime = txtime;
           m_stat.push_back(tmp);
        } 
  
   if (InetSocketAddress::IsMatchingType (from))
      {
         NS_LOG_INFO (" RX " << m_rxBytes 
                      << " " << InetSocketAddress::ConvertFrom (from).GetIpv4 () 
                      << " " << seqTs.GetSeq () 
                      << " " << packet->GetUid () 
                      << " TXtime: " << seqTs.GetTs () 
                      << " RXtime: " << now 
                      << " QoS Id : " << QosUtilsMapTidToAc (qosId)
                      << " Privacy ID : " << (u_int32_t)privacyId
                      << " Operation ID : " << opID
                      << " consumer Id : " << custId );
      }
   else if (Inet6SocketAddress::IsMatchingType (from))
      {
         NS_LOG_INFO ("TraceDelay: RX " << m_rxBytes <<
                      " bytes from "<< Inet6SocketAddress::ConvertFrom (from).GetIpv6 () <<
                      " Sequence Number: " << seqTs.GetSeq() <<
                      " Uid: " << packet->GetUid () <<
                      " TXtime: " << seqTs.GetTs () <<
                      " RXtime: " << Simulator::Now () <<
                      " Delay: " << Simulator::Now () - seqTs.GetTs ());
       }
}
bool LtePacketSink::IsThereAnyPreviousStoredPacket(Address from) {
    bool lfoundPacket = false;
    for(std::vector<DataWaitingPacket>::iterator it = m_waitingPacket.begin(); it != m_waitingPacket.end(); ++it) {
       if(it->from == from) {
          lfoundPacket=true;
          break;
       }
    }     
    return lfoundPacket;
}

void LtePacketSink::StatPrint () 
{
   std::ostringstream os;
   os << m_outputFilename+".sta";
   std::ofstream osf (os.str().c_str(), std::ios::out | std::ios::app);

   double totrxCount = 0;
   double totrxBytes = 0;
   double toteteDelay = 0;
   double maxCount = 0;
   double totCT = 0;
   Time minfirstRx;
   Time maxLastRx;
   uint32_t counter = 0;
   bool lfirst = true;
   for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
      totrxCount += it->rxCount;
      totrxBytes += it->rxBytes;
      if (maxCount < it->rxCount) maxCount = it->rxCount;
      if (lfirst) {
           minfirstRx = it->firstRxTime;
           maxLastRx = it->lastRxTime;
           lfirst = false;
      } else {
          if (minfirstRx > it->firstRxTime) minfirstRx = it->firstRxTime;
          if (maxLastRx < it->lastRxTime) maxLastRx = it->lastRxTime;
      }
      toteteDelay += it->totDelay;
      double ct = ((it->lastRxTime).ToInteger (Time::US) - (it->minTxTime).ToInteger (Time::US)); 
      totCT += ct;
      counter++;
      NS_LOG_INFO (it->round << " " << it->rxCount << " " << it->rxBytes << " " << it->totDelay << " " << 
            it->firstRxTime << " " << it->lastRxTime << " " << it->minTxTime << " " << ct);
      osf << it->round << " " << it->rxCount << " " << it->rxBytes << " " << it->totDelay << " " << it->firstRxTime << " " << it->lastRxTime << " " << it->minTxTime << " " << ct << std::endl;
      
   }
   osf.close();

   double delta = (maxLastRx.ToInteger (Time::US) - minfirstRx.ToInteger (Time::US))/1000000;  
   double pdr = 100*totrxCount/(maxCount*counter);
   double tp = (totrxBytes*8)/delta/1024;
   double ete = toteteDelay/totrxCount/1000000;  
   double avgCT = totCT/counter/1000000; // in seconds
   NS_LOG_INFO ("Statistic : " << totrxCount << " " << maxCount*counter << " " << totrxBytes << " " << maxLastRx << " " << minfirstRx << " "
                << delta << " " << toteteDelay << " " << totCT
                << " PDR " << pdr
                << " TP " << tp
                << " ETE Delay " << ete << " seconds "
                << " CT " << avgCT );
   std::ostringstream os1;
   os1 << m_outputFilename+".rcp";
   std::ofstream osf1 (os1.str().c_str(), std::ios::out | std::ios::app);
   osf1 << totrxCount << " " << maxCount*counter << " " << totrxBytes << " " << maxLastRx << " " << minfirstRx << " " << delta << " " << toteteDelay << " " << totCT << " PDR " << pdr << " TP " << tp << " ETE Delay " << ete << " seconds " << " CT " << avgCT << std::endl ;
   osf1.close();
   
}

void LtePacketSink::ReportStat (std::ostream & os)  
{
   NS_LOG_INFO(m_stat.size() );
 /*  double totrxCount = 0;
   double totrxBytes = 0;
   double toteteDelay = 0;
   double maxCount = 0;
   double totCT = 0;
   Time minfirstRx;
   Time maxLastRx;
   uint32_t counter = 0;
   bool lfirst = true;
   
   for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
    NS_LOG_INFO("Report Statistic to file test !");
      totrxCount += it->rxCount;
      totrxBytes += it->rxBytes;
      if (maxCount < it->rxCount) maxCount = it->rxCount;
      if (lfirst) {
           minfirstRx = it->firstRxTime;
           maxLastRx = it->lastRxTime;
           lfirst = false;
      } else {
          if (minfirstRx > it->firstRxTime) minfirstRx = it->firstRxTime;
          if (maxLastRx < it->lastRxTime) maxLastRx = it->lastRxTime;
      }
      toteteDelay += it->totDelay;
      double ct = ((it->lastRxTime).ToInteger (Time::US) - (it->minTxTime).ToInteger (Time::US)); 
      totCT += ct;
      counter++;
      NS_LOG_INFO (it->round << " " << it->rxCount << " " << it->rxBytes << " " << it->totDelay << " " << 
            it->firstRxTime << " " << it->lastRxTime << " " << it->minTxTime << " " << ct);
            
   }
   double delta = (maxLastRx.ToInteger (Time::US) - minfirstRx.ToInteger (Time::US))/1000000;  
   double pdr = 100*totrxCount/(maxCount*counter);
   double tp = (totrxBytes*8)/delta/1024;
   double ete = toteteDelay/totrxCount/1000000;  
   double avgCT = totCT/counter/1000000; // in seconds
   os << totrxCount << " " << maxCount*counter << " " << totrxBytes << " " << maxLastRx << " " << minfirstRx << " " << delta << " " << toteteDelay << " " << totCT << " PDR " << pdr << " TP " << tp << " ETE Delay " << ete << " seconds " << " CT " << avgCT << std::endl ;
   */
   
}

void LtePacketSink::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 
void LtePacketSink::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 

void LtePacketSink::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&LtePacketSink::HandleRead, this));
  m_socketList.push_back (s);
}

} // Namespace ns3
