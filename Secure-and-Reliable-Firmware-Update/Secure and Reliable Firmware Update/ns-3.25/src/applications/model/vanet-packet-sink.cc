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
#include "ns3/packet-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/seq-ts-header.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/qos-utils.h"
#include "vanet-packet-sink.h"
#include "seq-ts-header.h"


#include <iostream>
#include <sstream>
#include <fstream>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("VanetPacketSink");
NS_OBJECT_ENSURE_REGISTERED (VanetPacketSink);

TypeId 
VanetPacketSink::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::VanetPacketSink")
    .SetParent<Application> ()
    .AddConstructor<VanetPacketSink> ()
    .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&VanetPacketSink::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("ListenEV", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&VanetPacketSink::m_localEV),
                   MakeAddressChecker ())
    .AddAttribute ("Remote", "The Address of the destination.",
                   AddressValue (),
                   MakeAddressAccessor (&VanetPacketSink::m_target),
                   MakeAddressChecker ())
    .AddAttribute ("UDPTargetAddress", "The Address of the destination.",
                   AddressValue (),
                   MakeAddressAccessor (&VanetPacketSink::m_UDPTarget),
                   MakeAddressChecker ())
    .AddAttribute ("NumberOfNodes", "The default size of packets received",
                   UintegerValue (25),
                   MakeUintegerAccessor (&VanetPacketSink::m_nNodes),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DCRLMode", "Whether distributed certificate revocation list mode on or off",
                   UintegerValue (0),
                   MakeUintegerAccessor (&VanetPacketSink::m_DCRLMode),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&VanetPacketSink::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("DefaultRxSize", "The default size of packets received",
                   UintegerValue (80),
                   MakeUintegerAccessor (&VanetPacketSink::m_defSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Mode", "The default size of packets received",
                   UintegerValue (1),
                   MakeUintegerAccessor (&VanetPacketSink::m_mode),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Scenario", "The default size of packets received",
                   UintegerValue (1),
                   MakeUintegerAccessor (&VanetPacketSink::m_scenario),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("PacketSize", "The default size of packets to be sent",
                   UintegerValue (512),
                   MakeUintegerAccessor (&VanetPacketSink::m_pktSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MeterType", "[0]->GW, [1]->AGG, [2]->LEAF",
                   UintegerValue (1),
                   MakeUintegerAccessor (&VanetPacketSink::m_meterType),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Delay", "The default size of packets received",
                   UintegerValue (0),
                   MakeUintegerAccessor (&VanetPacketSink::m_procDelay),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Child", "The number of child meters of this meter",
                   UintegerValue (1),
                   MakeUintegerAccessor (&VanetPacketSink::m_childNum),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("LeafMeters", "The number of child meters of this meter",
                   UintegerValue (1),
                   MakeUintegerAccessor (&VanetPacketSink::m_leafMeters),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("FileName", "The output filename",
                   StringValue ("roundstat"),
                   MakeStringAccessor (&VanetPacketSink::m_outputFilename),
                   MakeStringChecker ())
    .AddAttribute ("OperationIdentifier", "The identifier for the operation",
                    UintegerValue (0),
                    MakeUintegerAccessor (&VanetPacketSink::m_operationId),
                    MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Port", "Port on which we listen for incoming packets.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&VanetPacketSink::m_UDPPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("MultipleTargets", "Whether there are multiple targets.",
                   UintegerValue (0),
                   MakeUintegerAccessor (&VanetPacketSink::m_multTargetFlag),
                   MakeUintegerChecker<uint8_t> ())
    .AddTraceSource ("Rx", "A packet has been received",
                     MakeTraceSourceAccessor (&VanetPacketSink::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&VanetPacketSink::m_txTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

VanetPacketSink::VanetPacketSink ()
{
  NS_LOG_FUNCTION (this);
  m_targetSocket = 0;
  m_UDPTargetSocket = 0;
  m_connected = false;
  m_socket = 0;
  m_totalRx = 0;
  m_seqnum = 0;
  m_totBytes = 0;
  m_lastStartTime = Seconds (0);
  m_meterType = 0;
  m_mode = 0;
  m_scenario = 1;
  m_childNum = 0;
  m_nNodes = 25;
}

VanetPacketSink::VanetPacketSink (uint16_t port, Address local, uint32_t delay)
{
  NS_LOG_FUNCTION (this);
  m_targetSocket = 0;
  m_UDPTargetSocket = 0;
  m_connected = false;
  m_socket = 0;
  m_UDPPort = port;
  m_local = local;
  m_totalRx = 0;
  m_seqnum = 0;
  m_procDelay = delay;
  m_totBytes = 0;
  m_lastStartTime = Seconds (0);
  m_meterType = 0;
  m_mode = 0;
  m_scenario = 1;
  m_childNum = 0;
  m_nNodes = 25;
}

VanetPacketSink::~VanetPacketSink()
{
  NS_LOG_FUNCTION (this);
  m_UDPsocket = 0;
  m_UDPsocket6 = 0;
  StatPrint();
}

uint32_t VanetPacketSink::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}

Ptr<Socket>
VanetPacketSink::GetListeningSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}

std::list<Ptr<Socket> >
VanetPacketSink::GetAcceptedSockets (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socketList;
}

void VanetPacketSink::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_targetSocket = 0;
  m_UDPTargetSocket = 0;
  m_socketList.clear ();
  m_targetSockets.clear();

  // chain up
  Application::DoDispose ();
}

// Application Methods
void VanetPacketSink::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  
  ///////////////////////////////UDP////////////////////////////////////
  if (m_UDPsocket == 0)
    {
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_UDPsocket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), m_UDPPort);
      m_UDPsocket->Bind (local);
      if (addressUtils::IsMulticast (m_UDPlocal))
        {
          Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_UDPsocket);
          if (udpSocket)
            {
              // equivalent to setsockopt (MCAST_JOIN_GROUP)
              udpSocket->MulticastJoinGroup (0, m_UDPlocal);
            }
          else
            {
              NS_FATAL_ERROR ("Error: Failed to join multicast group");
            }
        }
    }

  if (m_UDPsocket6 == 0)
    {
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_UDPsocket6 = Socket::CreateSocket (GetNode (), tid);
      Inet6SocketAddress local6 = Inet6SocketAddress (Ipv6Address::GetAny (), m_UDPPort);
      m_UDPsocket6->Bind (local6);
      if (addressUtils::IsMulticast (local6))
        {
          Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_UDPsocket6);
          if (udpSocket)
            {
              // equivalent to setsockopt (MCAST_JOIN_GROUP)
              udpSocket->MulticastJoinGroup (0, local6);
            }
          else
            {
              NS_FATAL_ERROR ("Error: Failed to join multicast group");
            }
        }
    }

  m_UDPsocket->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadUDP, this));
  m_UDPsocket6->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadUDP, this));
  

////////////////////////////////////TCP/////////////////////////////////////////
  
    //[0]->GW, [1]->AGG, [2]->LEAF
  
    // Create the socket if not already
    //GW
    if(m_meterType == (uint32_t)0){
        if(!m_localTCPsocket){
            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
            m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);
            m_localTCPsocket->Bind (m_local);

            m_localTCPsocket->Listen ();

    //        m_localTCPsocket->ShutdownSend ();

            m_localTCPsocket->SetAcceptCallback (
                MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                MakeCallback (&VanetPacketSink::HandleAcceptMesh, this));
            m_localTCPsocket->SetCloseCallbacks (
                MakeCallback (&VanetPacketSink::HandlePeerClose, this),
                MakeCallback (&VanetPacketSink::HandlePeerError, this));

            m_localTCPsocket->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadTCP, this));
        }
    }
    else if(m_meterType == (uint32_t)2){    //meshToEV Meter
//        if(!m_UDPsocket){
//            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
//            m_UDPsocket = Socket::CreateSocket (GetNode (), tid);
//            m_UDPsocket->Bind (m_localEV);
//
//            m_UDPsocket->Listen ();
//
//    //        m_localTCPsocket->ShutdownSend ();
//
//            m_UDPsocket->SetAcceptCallback (
//                MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
//                MakeCallback (&VanetPacketSink::HandleAcceptEV, this));
//            m_UDPsocket->SetCloseCallbacks (
//                MakeCallback (&VanetPacketSink::HandlePeerClose, this),
//                MakeCallback (&VanetPacketSink::HandlePeerError, this));
//
//            m_UDPsocket->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadEV, this));
//        }
        
        if (!m_socket){
            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
            m_socket = Socket::CreateSocket (GetNode (), tid);

            if (Inet6SocketAddress::IsMatchingType (m_target)){
                m_socket->Bind6 ();
            }
            else if (InetSocketAddress::IsMatchingType (m_target) ||
             PacketSocketAddress::IsMatchingType (m_target)){
                m_socket->Bind ();
            }

            m_socket->Connect (m_target);
            m_socket->SetAllowBroadcast (true);
//            m_socket->ShutdownRecv ();

            m_socket->SetConnectCallback (
                        MakeCallback (&VanetPacketSink::ConnectionSucceeded, this),
                        MakeCallback (&VanetPacketSink::ConnectionFailed, this));

            m_socket->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadTCP, this));
        }
    }  
}

void VanetPacketSink::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  while(!m_socketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front ();
      m_socketList.pop_front ();
      acceptedSocket->Close ();
    }
  while(!m_targetSockets.empty()){
      Ptr<Socket> targetSocket = m_targetSockets.front();
      m_targetSockets.pop_front();
      targetSocket->Close();
  }
  if (m_socket) 
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
  
  CancelEvents ();
  if(m_targetSocket != 0)
    {
      m_targetSocket->Close ();
    }
  else
    {
      NS_LOG_WARN ("VanetPacketSink found null socket to close in StopApplication");
    }
  
  ///////////////////////////////UDP////////////////////////////////////
  if (m_UDPsocket != 0) 
    {
      m_UDPsocket->Close ();
      m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
  if (m_UDPsocket6 != 0) 
    {
      m_UDPsocket6->Close ();
      m_UDPsocket6->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
  
}

void VanetPacketSink::CancelEvents ()
{
  NS_LOG_FUNCTION (this);

  if (m_sendEvent.IsRunning ())
    { // Cancel the pending send packet event
      // Calculate residual bits since last packet sent
      Time delta (Simulator::Now () - m_lastStartTime);
    }
  Simulator::Cancel (m_sendEvent);
}

void VanetPacketSink::HandleReadTCP (Ptr<Socket> socket) {
    NS_LOG_FUNCTION (this << socket);
    Ptr<Packet> packet;
    Address from;
    
    while ((packet = socket->RecvFrom (from))) {
        if (packet->GetSize () == 0) { //EOF
            break;
        }
        
        uint16_t m_pktsize = packet->GetSize();
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
          HandleReport(m_prevPacket, from, socket);
      } else {
        // two cases, > and <, if higher, split them
      	if (m_pktsize > m_defSize) {
      	    uint16_t m_begin = 0;
      	    uint16_t m_length = m_defSize;
      	    while (m_pktsize >= m_defSize) {
//                NS_LOG_INFO("Split packet : " << m_pktsize << " from : " << m_begin << " length " << m_length);
      	        Ptr<Packet> frag = m_prevPacket->CreateFragment(m_begin, m_length);
      	        HandleReport(frag, from, socket);
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
//               NS_LOG_INFO("add the rest of the packet in the waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
      	    }
      	} else {
           DataWaitingPacket tmp;
           tmp.from = from;
           tmp.pkt  = m_prevPacket;
           m_waitingPacket.push_back(tmp);
           NS_LOG_INFO("add waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
      	} // end of else m_pktsize > m_defSize
      } // end else m_pktsize == m_defSize  
  }
}

void VanetPacketSink::HandleReport(Ptr<Packet> packet, Address from, Ptr<Socket> socket) {
    //[0]->GW, [1]->AGG, [2]->LEAF

    if(m_meterType == (uint32_t)0){
        if (InetSocketAddress::IsMatchingType (from)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s GW received " << packet->GetSize () << " bytes from " <<
            InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
            InetSocketAddress::ConvertFrom (from).GetPort ());
        }
        else if (Inet6SocketAddress::IsMatchingType (from)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s GW received " << packet->GetSize () << " bytes from " <<
            Inet6SocketAddress::ConvertFrom (from).GetIpv6 () << " port " <<
            Inet6SocketAddress::ConvertFrom (from).GetPort ());
        }

        packet->RemoveAllPacketTags ();
        packet->RemoveAllByteTags ();

        Simulator::Schedule (NanoSeconds (m_procDelay), &VanetPacketSink::SendToTargetSocket, this, packet, socket);
    }
    else if(m_meterType == (uint32_t)2){
        if (InetSocketAddress::IsMatchingType (from)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                        "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                        ") received " << packet->GetSize () << " bytes from GW " <<
                        InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                        InetSocketAddress::ConvertFrom (from).GetPort ());
        }
        else if (Inet6SocketAddress::IsMatchingType (from)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                        "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                        ") received " << packet->GetSize () << " bytes from GW " <<
                        Inet6SocketAddress::ConvertFrom (from).GetIpv6 () << " port " <<
                        Inet6SocketAddress::ConvertFrom (from).GetPort ());
        }

        packet->RemoveAllPacketTags ();
        packet->RemoveAllByteTags ();

        Simulator::ScheduleNow (&VanetPacketSink::EchoPacket, this, packet);
    }
    else{
        NS_LOG_INFO("We have a problem with meter type!");
    }
}

void VanetPacketSink::HandleReadUDP (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);

    m_EVsocket = socket;
    
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom (from))){
        if (InetSocketAddress::IsMatchingType (from))
        {
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                        "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                        ") received " << packet->GetSize () << " bytes from " <<
                        InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                        InetSocketAddress::ConvertFrom (from).GetPort ());
        }
        else if (Inet6SocketAddress::IsMatchingType (from))
        {
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                        "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                        ") received " << packet->GetSize () << " bytes from " <<
                        Inet6SocketAddress::ConvertFrom (from).GetIpv6 () << " port " <<
                        Inet6SocketAddress::ConvertFrom (from).GetPort ());
        }
        
        m_EVfrom = from;
        
        uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
        
        MeterSeqNumMap::iterator itSeq;
        itSeq = m_SocketAddressMap.find(hostOrderIpAddress);
        
        if(itSeq != m_SocketAddressMap.end())
            m_SocketAddressMap.erase(hostOrderIpAddress);
        
        m_SocketAddressMap.insert(std::make_pair(hostOrderIpAddress, std::make_pair(socket, from)));

        packet->RemoveAllPacketTags ();
        packet->RemoveAllByteTags ();
        
        SeqTsHeader header;
        header.SetSeq(hostOrderIpAddress);
        packet = Create<Packet> (packet->GetSize()-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        if(m_DCRLMode){
//            NS_LOG_INFO("DCRL Mode: " << m_DCRLMode);
            Simulator::Schedule (NanoSeconds (m_procDelay), &VanetPacketSink::EchoPacket, this, packet);
        }
        else{
            Simulator::Schedule (NanoSeconds (m_procDelay), &VanetPacketSink::SendToTarget, this, packet);
        }

//        Simulator::Schedule (Seconds(2.0), &VanetPacketSink::EchoPacket, this, packet);
    }
}

void VanetPacketSink::HandleReadEV (Ptr<Socket> socket) {
    NS_LOG_FUNCTION (this << socket);
    Ptr<Packet> packet;
    Address from;
    
    while ((packet = socket->RecvFrom (from))) {
        if (packet->GetSize () == 0) { //EOF
            break;
        }
        
        uint16_t m_pktsize = packet->GetSize();
        // check whether there is a previous save packet first
        Ptr<Packet> m_prevPacket = packet;
      
        //==============================================================================      
        //      if(packet->GetSize () == 80)
        //        HandleReport(m_prevPacket,from);
        //==============================================================================
      
        uint16_t m_savePktSize = 0;
        if (IsThereAnyPreviousStoredPacket(from)) {
            for(std::vector<DataWaitingPacket>::iterator it = m_waitingPacketEV.begin(); it != m_waitingPacketEV.end(); ++it) {
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
            if (m_waitingPacketEV.size() > 1) {
                std::vector<DataWaitingPacket> tmp (m_waitingPacketEV); // copy to temp
                m_waitingPacketEV.clear();

                for(std::vector<DataWaitingPacket>::iterator itw = tmp.begin() ; itw != tmp.end(); ++itw) {
                    if(itw->from != from) { // keep maintain in the waiting list
                        DataWaitingPacket keep;
                        keep.from = itw->from;
                        keep.pkt   = itw->pkt;
                        m_waitingPacketEV.push_back(keep);
                        NS_LOG_INFO("Keep waiting packet " << keep.from << " " << keep.pkt->GetSize() << " " << m_waitingPacketEV.size () );
                    }
                }
            } else m_waitingPacketEV.clear();
        } else m_prevPacket = packet; // there were saved packets, but none was from this address
      
      if (m_pktsize == m_defSize) {
          HandleReportEV(m_prevPacket, from, socket);
      } else {
        // two cases, > and <, if higher, split them
      	if (m_pktsize > m_defSize) {
      	    uint16_t m_begin = 0;
      	    uint16_t m_length = m_defSize;
      	    while (m_pktsize >= m_defSize) {
//                NS_LOG_INFO("Split packet : " << m_pktsize << " from : " << m_begin << " length " << m_length);
      	        Ptr<Packet> frag = m_prevPacket->CreateFragment(m_begin, m_length);
      	        HandleReportEV(frag, from, socket);
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
               m_waitingPacketEV.push_back(tmp);
//               NS_LOG_INFO("add the rest of the packet in the waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
      	    }
      	} else {
           DataWaitingPacket tmp;
           tmp.from = from;
           tmp.pkt  = m_prevPacket;
           m_waitingPacketEV.push_back(tmp);
           NS_LOG_INFO("add waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacketEV.size () );               
      	} // end of else m_pktsize > m_defSize
      } // end else m_pktsize == m_defSize  
  }
}

void VanetPacketSink::HandleReportEV(Ptr<Packet> packet, Address from, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);

    m_EVsocket = socket;

    if (InetSocketAddress::IsMatchingType (from)){
        NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                    "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                    ") received " << packet->GetSize () << " bytes from an EV at " <<
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                    InetSocketAddress::ConvertFrom (from).GetPort ());
    }
    else if (Inet6SocketAddress::IsMatchingType (from)){
        NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << 
                    "s Mesh-To-EV meter (Node " << GetNode()->GetId() << 
                    ") received " << packet->GetSize () << " bytes from " <<
                    Inet6SocketAddress::ConvertFrom (from).GetIpv6 () << " port " <<
                    Inet6SocketAddress::ConvertFrom (from).GetPort ());
    }

    m_EVfrom = from;

    uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();

    NS_LOG_INFO("Host Order IP Address: " << hostOrderIpAddress);

    MeterSeqNumMap::iterator itSeq;
    itSeq = m_SocketAddressMap.find(hostOrderIpAddress);

    if(itSeq != m_SocketAddressMap.end())
        m_SocketAddressMap.erase(hostOrderIpAddress);

    m_SocketAddressMap.insert(std::make_pair(hostOrderIpAddress, std::make_pair(socket, from)));

    packet->RemoveAllPacketTags ();
    packet->RemoveAllByteTags ();

    SeqTsHeader header;
    header.SetSeq(hostOrderIpAddress);
    packet = Create<Packet> (packet->GetSize()-(header.GetSerializedSize()));
    packet->AddHeader(header);

    if(m_DCRLMode){
    //            NS_LOG_INFO("DCRL Mode: " << m_DCRLMode);
        Simulator::Schedule (NanoSeconds (m_procDelay), &VanetPacketSink::EchoPacket, this, packet);
    }
    else{
        Simulator::Schedule (NanoSeconds (m_procDelay), &VanetPacketSink::SendToTarget, this, packet);
    }
}

void VanetPacketSink::EchoPacket (Ptr<Packet> packet){
    NS_LOG_FUNCTION(this << packet << " Node: " << GetNode()->GetId());
    SeqTsHeader header;
    packet->PeekHeader(header);
    uint32_t hostOrderIpAddress = header.GetSeq();
    
    NS_LOG_INFO("Host Order IP Address: " << hostOrderIpAddress);
    
    MeterSeqNumMap::iterator itSeq;
    itSeq = m_SocketAddressMap.find(hostOrderIpAddress);
    
    if(itSeq == m_SocketAddressMap.end())
        NS_LOG_INFO("We have a big problem, captain!!!");
    
    Ptr<Socket> socket = itSeq->second.first;
    Address from = itSeq->second.second;
    
    NS_LOG_LOGIC ("Echoing packet");
    socket->SendTo (packet, 0, from);

//    if (InetSocketAddress::IsMatchingType (m_EVfrom))
//    {
//      NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s server sent " << packet->GetSize () << " bytes to " <<
//                   InetSocketAddress::ConvertFrom (m_EVfrom).GetIpv4 () << " port " <<
//                   InetSocketAddress::ConvertFrom (m_EVfrom).GetPort ());
//    }
//    else if (Inet6SocketAddress::IsMatchingType (m_EVfrom))
//    {
//      NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s server sent " << packet->GetSize () << " bytes to " <<
//                   Inet6SocketAddress::ConvertFrom (m_EVfrom).GetIpv6 () << " port " <<
//                   Inet6SocketAddress::ConvertFrom (m_EVfrom).GetPort ());
//    }
}

void VanetPacketSink::SendToTarget(Ptr<Packet> packet){
    NS_LOG_LOGIC ("SendToTarget::Send the Request to the target");
    
    if (!m_socket){
        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
        m_socket = Socket::CreateSocket (GetNode (), tid);
        
        if (Inet6SocketAddress::IsMatchingType (m_target)){
            m_socket->Bind6 ();
        }
        else if (InetSocketAddress::IsMatchingType (m_target) ||
         PacketSocketAddress::IsMatchingType (m_target)){
            m_socket->Bind ();
        }

        m_socket->Connect (m_target);
        m_socket->SetAllowBroadcast (true);
//        m_socket->ShutdownRecv ();

        m_socket->SetConnectCallback (
            MakeCallback (&VanetPacketSink::ConnectionSucceeded, this),
            MakeCallback (&VanetPacketSink::ConnectionFailed, this));

        m_socket->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadTCP, this));
        
        NS_LOG_INFO("Connection Establishment WHEN THE FIRST PACKET SENT");
    }
    
    m_txTrace (packet);
    m_socket->Send (packet);
    
//    if (InetSocketAddress::IsMatchingType (m_target)){
//        NS_LOG_INFO (" Tx " << packet->GetSize() 
//                   << " " << InetSocketAddress::ConvertFrom(m_target).GetIpv4 ()
//                   << ":" << InetSocketAddress::ConvertFrom(m_target).GetPort()
//                   <<" Uid " << packet->GetUid () 
//                   <<" Time " << (Simulator::Now ()).GetSeconds ());
//    }
//    else if (Inet6SocketAddress::IsMatchingType (m_target)){
//        NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
//                    << "s on-off application sent "
//                    <<  packet->GetSize () << " bytes to "
//                    << Inet6SocketAddress::ConvertFrom(m_target).GetIpv6 ()
//                    << " port " << Inet6SocketAddress::ConvertFrom (m_target).GetPort ());
//    }
}

void VanetPacketSink::SendToTargetSocket(Ptr<Packet> packet, Ptr<Socket> socket){
    NS_LOG_LOGIC ("SendToTargetSocket::Send the Request to the target");
    
    m_txTrace (packet);
    socket->Send (packet);
}

void VanetPacketSink::SendPacket (uint32_t seqNum)
{
  NS_LOG_FUNCTION (this);
 // Create the socket if not already

  //NS_ASSERT (m_sendEvent.IsExpired ());
  SeqTsHeader seqTs;
  seqTs.SetSeq (seqNum);
  NS_LOG_INFO ("PacketSink: Size of seqTs: " << seqTs.GetSerializedSize());
  Ptr<Packet> packet = Create<Packet> (m_pktSize-(seqTs.GetSerializedSize()));
  packet->AddHeader (seqTs);
  
  m_txTrace (packet);
  m_targetSocket->Send (packet);
  m_totBytes += m_pktSize;
  if (InetSocketAddress::IsMatchingType (m_target))
    {
      //++m_seqnum;
      NS_LOG_INFO ("PacketSink: Tx " << packet->GetSize() 
                   << " " << InetSocketAddress::ConvertFrom(m_target).GetIpv4 ()
                   << ":" << InetSocketAddress::ConvertFrom(m_target).GetPort()
                   <<" Uid " << packet->GetUid () 
                   << " Sequence Number: " << seqTs.GetSeq () 
                   <<" Time " << (Simulator::Now ()).GetSeconds ());
    }
  else if (Inet6SocketAddress::IsMatchingType (m_target))
    {
      NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                   << "s on-off application sent "
                   <<  packet->GetSize () << " bytes to "
                   << Inet6SocketAddress::ConvertFrom(m_target).GetIpv6 ()
                   << " port " << Inet6SocketAddress::ConvertFrom (m_target).GetPort ()
                   << " total Tx " << m_totBytes << " bytes");
    }
  m_lastStartTime = Simulator::Now ();
}

void VanetPacketSink::SendUDPPacket ()
{
  NS_LOG_FUNCTION (this);
 // Create the socket if not already

  //NS_ASSERT (m_sendEvent.IsExpired ());
  SeqTsHeader seqTs;
  seqTs.SetSeq (m_seqnum);
  NS_LOG_INFO ("PacketSink: Size of seqTs: " << seqTs.GetSerializedSize());
  Ptr<Packet> packet = Create<Packet> (m_pktSize-(seqTs.GetSerializedSize()));
  packet->AddHeader (seqTs);
  
  m_txTrace (packet);
  m_UDPTargetSocket->Send (packet);
  m_totBytes += m_pktSize;
  if (InetSocketAddress::IsMatchingType (m_UDPTarget))
    {
      ++m_seqnum;
      NS_LOG_INFO ("PacketSink: Tx " << packet->GetSize() 
                   << " " << InetSocketAddress::ConvertFrom(m_UDPTarget).GetIpv4 ()
                   << ":" << InetSocketAddress::ConvertFrom(m_UDPTarget).GetPort()
                   <<" Uid " << packet->GetUid () 
                   << " Sequence Number: " << seqTs.GetSeq () 
                   <<" Time " << (Simulator::Now ()).GetSeconds ());
    }
  else if (Inet6SocketAddress::IsMatchingType (m_UDPTarget))
    {
      NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                   << "s on-off application sent "
                   <<  packet->GetSize () << " bytes to "
                   << Inet6SocketAddress::ConvertFrom(m_UDPTarget).GetIpv6 ()
                   << " port " << Inet6SocketAddress::ConvertFrom (m_UDPTarget).GetPort ()
                   << " total Tx " << m_totBytes << " bytes");
    }
  m_lastStartTime = Simulator::Now ();
}

void VanetPacketSink::ConnectionSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_INFO("Node " << GetNode()->GetId() << 
              " successfully established a TCP connection at " << Simulator::Now().GetSeconds() << " s!!!");
  m_connected = true;
}

void VanetPacketSink::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_INFO("Connection Failed");
}

bool VanetPacketSink::IsThereAnyPreviousStoredPacket(Address from) {
    bool lfoundPacket = false;
    for(std::vector<DataWaitingPacket>::iterator it = m_waitingPacket.begin(); it != m_waitingPacket.end(); ++it) {
       if(it->from == from) {
          lfoundPacket=true;
          break;
       }
    }     
    return lfoundPacket;
}

void VanetPacketSink::StatPrint () 
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
   uint32_t roundCounter = 0;
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
      if(it->rxCount == m_childNum){
        totCT += ct;
        roundCounter++;
      }
      counter++;
      NS_LOG_INFO (it->round << " " << it->rxCount << " " << it->rxBytes << " " << it->totDelay << " " << 
            it->firstRxTime << " " << it->lastRxTime << " " << it->minTxTime << " " << ct);
      osf << it->round << " " << it->rxCount << " " << it->rxBytes << " " << it->totDelay << " " << it->firstRxTime << " " << it->lastRxTime << " " << it->minTxTime << " " << ct << std::endl;
      
   }
   osf.close();
   
   double pdr = 0.0;
   double delta = (maxLastRx.ToInteger (Time::US) - minfirstRx.ToInteger (Time::US))/1000000; 
   if(m_mode == (uint32_t)0)
       pdr =  100*totrxCount/(counter*m_leafMeters);
   else
       pdr =  100*totrxCount/(maxCount*counter);
   double tp = (totrxBytes*8)/delta/1024;
   double ete = toteteDelay/totrxCount/1000000;  
   double avgCT = totCT/roundCounter/1000000; // in seconds
   avgCT += (((double)m_procDelay)/1000000000.0);
//   NS_LOG_INFO ("Statistic : " << totrxCount << " " << maxCount*counter << " " << totrxBytes << " " << maxLastRx << " " << minfirstRx << " "
//                << delta << " " << toteteDelay << " " << totCT
//                << " PDR " << pdr
//                << " TP " << tp
//                << " ETE Delay " << ete << " seconds "
//                << " CT " << avgCT );
   std::ostringstream os1;
   os1 << m_outputFilename+".rcp";
   std::ofstream osf1 (os1.str().c_str(), std::ios::out | std::ios::app);
   osf1 << totrxCount << " " << maxCount*counter << " " << totrxBytes << " " << maxLastRx << " " << minfirstRx << " " << delta << " " << toteteDelay << " " << totCT << " PDR " << pdr << " TP " << tp << " ETE Delay " << ete << " seconds " << " CT " << avgCT << std::endl ;
   osf1.close();
}

void VanetPacketSink::ReportStat (std::ostream & os)  
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

void VanetPacketSink::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 
void VanetPacketSink::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 

void VanetPacketSink::HandleAcceptEV (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadEV, this));
  m_socketList.push_back (s);
}

void VanetPacketSink::HandleAcceptMesh (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&VanetPacketSink::HandleReadTCP, this));
  m_socketList.push_back (s);
}

} // Namespace ns3