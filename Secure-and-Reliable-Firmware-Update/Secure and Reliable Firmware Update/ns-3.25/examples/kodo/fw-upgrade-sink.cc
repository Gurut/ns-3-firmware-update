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
#include "fw-upgrade-sink.h"
#include "seq-ts-header.h"
#include "ns3/packet.h"

#include <ns3/double.h>

#include <unistd.h>

#include <iostream>
#include <sstream>
#include <fstream>

namespace ns3 {
    NS_LOG_COMPONENT_DEFINE ("FWUpgradeSinkNW");
    NS_OBJECT_ENSURE_REGISTERED (FWUpgradeSink);

    TypeId FWUpgradeSink::GetTypeId (void){
        static TypeId tid = TypeId ("ns3::FWUpgradeSinkNW")
            .SetParent<Application> ()
            .AddConstructor<FWUpgradeSink> ()
            .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                           AddressValue (),
                           MakeAddressAccessor (&FWUpgradeSink::m_local),
                           MakeAddressChecker ())
            .AddAttribute ("Remote", "The Address of the destination.",
                           AddressValue (),
                           MakeAddressAccessor (&FWUpgradeSink::m_target),
                           MakeAddressChecker ())
            .AddAttribute ("UDPTargetAddress", "The Address of the destination.",
                           AddressValue (),
                           MakeAddressAccessor (&FWUpgradeSink::m_UDPTarget),
                           MakeAddressChecker ())
            .AddAttribute ("NSMs", 
                           "The number of smart meters in the network",
                           UintegerValue (36),
                           MakeUintegerAccessor (&FWUpgradeSink::m_nSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("NChildSMs", 
                           "The maximum number of packets the application will send",
                           UintegerValue (3),
                           MakeUintegerAccessor (&FWUpgradeSink::m_nChildSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("NTargetedSMs", 
                           "The maximum number of packets the application will send",
                           UintegerValue (10),
                           MakeUintegerAccessor (&FWUpgradeSink::m_nTargetedSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("DCRLMode", "Whether distributed certificate revocation list mode on or off",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSink::m_DCRLMode),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                           TypeIdValue (UdpSocketFactory::GetTypeId ()),
                           MakeTypeIdAccessor (&FWUpgradeSink::m_tid),
                           MakeTypeIdChecker ())
            .AddAttribute ("SigncryptedChallengeSize", "The default size of packets received",
                           UintegerValue (1013),
                           MakeUintegerAccessor (&FWUpgradeSink::m_SCH_Up),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("REQSignatureSize", "The default size of packets to be sent",
                           UintegerValue (1608),
                           MakeUintegerAccessor (&FWUpgradeSink::m_REQSignatureSize),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Mode", "The default size of packets received",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSink::m_mode),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Scenario", "The default size of packets received",
                           UintegerValue (1),
                           MakeUintegerAccessor (&FWUpgradeSink::m_scenario),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("MeterType", "[0]->GW, [1]->AGG, [2]->LEAF",
                           UintegerValue (1),
                           MakeUintegerAccessor (&FWUpgradeSink::m_meterType),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Delay", "The default size of packets received",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSink::m_procDelay),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Child", "The number of child meters of this meter",
                           UintegerValue (1),
                           MakeUintegerAccessor (&FWUpgradeSink::m_childNum),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("LeafMeters", "The number of child meters of this meter",
                           UintegerValue (1),
                           MakeUintegerAccessor (&FWUpgradeSink::m_leafMeters),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("FileName", "The output filename",
                           StringValue ("roundstat"),
                           MakeStringAccessor (&FWUpgradeSink::m_outputFilename),
                           MakeStringChecker ())
            .AddAttribute ("OperationIdentifier", "The identifier for the operation",
                            UintegerValue (0),
                            MakeUintegerAccessor (&FWUpgradeSink::m_operationId),
                            MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Port", "Port on which we listen for incoming packets.",
                           UintegerValue (10),
                           MakeUintegerAccessor (&FWUpgradeSink::m_UDPPort),
                           MakeUintegerChecker<uint16_t> ())
            .AddAttribute ("MultipleTargets", "Whether there are multiple targets.",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSink::m_multTargetFlag),
                           MakeUintegerChecker<uint8_t> ())
            .AddAttribute ("ActiveTimePeriod",
                           "The time period in which the gateway and other SMs can communicate data",
                           DoubleValue (400.0),
                           MakeDoubleAccessor (&FWUpgradeSink::m_activeTP),
                           MakeDoubleChecker<double> ())
            .AddAttribute ("FirstSending",
                           "The time period in which the gateway and other SMs can communicate data",
                           TimeValue (Seconds(100.0)),
                           MakeTimeAccessor (&FWUpgradeSink::m_firstSendTime),
                           MakeTimeChecker())
            .AddTraceSource ("Rx", "A packet has been received",
                             MakeTraceSourceAccessor (&FWUpgradeSink::m_rxTrace),
                             "ns3::Packet::TracedCallback")
            .AddTraceSource ("Tx", "A new packet is created and is sent",
                             MakeTraceSourceAccessor (&FWUpgradeSink::m_txTrace),
                             "ns3::Packet::TracedCallback");
        return tid;
    }

    FWUpgradeSink::FWUpgradeSink (){
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
        m_rxCount = 0.0;
        m_nRecACKs = 0;
        m_bDelayFlag = true;
        m_batchCounter = 0;
    }

    FWUpgradeSink::FWUpgradeSink (uint16_t port, Address local, uint32_t delay){
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
        m_rxCount = 0.0;
        m_nRecACKs = 0;
        m_bDelayFlag = true;
        m_batchCounter = 0;
    }
    
    FWUpgradeSink::FWUpgradeSink(kodocpp::codec codeType,
                                 kodocpp::field field,
                                 uint32_t generationSize,
                                 uint32_t packetSize)
                                : m_codeType (codeType),
                                  m_field (field),
                                  m_generationSize (generationSize),
                                  m_packetSize (packetSize){
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
        m_rxCount = 0.0;
        m_nRecACKs = 0;
        m_bDelayFlag = true;
        m_batchCounter = 0;
        
        srand(static_cast<uint32_t>(time(0)));
        
        // Create the encoder factory using the supplied parameters
        kodocpp::encoder_factory encoderFactory (m_codeType, m_field, m_generationSize, m_packetSize);
        
        // Create encoder and disable systematic mode
        m_encoder = encoderFactory.build ();
        m_encoder.set_systematic_off ();
        
        // Initialize the encoder data buffer
        m_encoderBuffer.resize (m_encoder.block_size ());
        
        for(int i=0; i<(int)m_encoderBuffer.size(); i++){
            m_encoderBuffer[i] = (char)((i%26)+97);
//            NS_LOG_INFO("Buffer[" << i << "]: " << (char)m_encoderBuffer[i]);
        }
        
//        SeqTsHeader header;
//        header.SetSeq(111);
//        Ptr<Packet> pkt = Create<Packet>(15700);
//        pkt->AddHeader(header);
//        pkt->CopyData(&m_encoderBuffer[0], m_encoderBuffer.size());
        m_encoder.set_const_symbols (m_encoderBuffer.data (), m_encoder.block_size ());
        
//        NS_LOG_INFO("Size of the packet: " << pkt->GetSize());
//        NS_LOG_INFO("Serialized size of the packet: " << pkt->GetSerializedSize());
//        NS_LOG_INFO("Encoder Buffer Size: " << m_encoderBuffer.size());
//        NS_LOG_INFO("Encoder Payload Size: " << m_encoder.payload_size ());
//        for(int i=0; i<(int)m_encoderBuffer.size(); i++)
//            NS_LOG_INFO("Buffer[" << i << "]: " << (uint32_t)m_encoderBuffer[i]);
        
        m_payload.resize (m_encoder.payload_size ());
        
        // Initialize transmission count
        m_transmissionCount = 0;
    }
    
    FWUpgradeSink::FWUpgradeSink(kodocpp::codec codeType,
                                 kodocpp::field field,
                                 uint32_t generationSize,
                                 uint32_t packetSize,
                                 uint32_t batchSize)
                                : m_codeType (codeType),
                                  m_field (field),
                                  m_generationSize (generationSize),
                                  m_packetSize (packetSize),
                                  m_nBatches (batchSize){
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
        m_rxCount = 0.0;
        m_nRecACKs = 0;
        m_bDelayFlag = true;
        m_batchCounter = 0;
        
        srand(static_cast<uint32_t>(time(0)));
        
        // Create the encoder factory using the supplied parameters
        kodocpp::encoder_factory encoderFactory (m_codeType, m_field, m_generationSize, m_packetSize);
        
        m_encoders.resize(m_nBatches);
        m_encoderBuffers.resize(m_nBatches);
        m_payloads.resize (m_nBatches);
        m_IpTimeStampMaps.resize(m_nBatches);
        
        for(int i=0; i<(int)m_nBatches; i++){
            // Create encoder and disable systematic mode
            m_encoders[i] = encoderFactory.build ();
            m_encoders[i].set_systematic_off ();
            
            // Initialize the encoder data buffer
            m_encoderBuffers[i].resize (m_encoders[i].block_size ());
            
            for(int j=0; j<(int)m_encoderBuffers[i].size(); j++){
                m_encoderBuffers[i][j] = (char)((j%26)+97);
//                NS_LOG_INFO("Buffer[" << j << "]: " << (char)m_encoderBuffer[j]);
            }
            m_encoders[i].set_const_symbols (m_encoderBuffers[i].data (), m_encoders[i].block_size ());
            m_payloads[i].resize (m_encoders[i].payload_size ());
        }
//        SeqTsHeader header;
//        header.SetSeq(111);
//        Ptr<Packet> pkt = Create<Packet>(15700);
//        pkt->AddHeader(header);
//        pkt->CopyData(&m_encoderBuffer[0], m_encoderBuffer.size());
        
//        NS_LOG_INFO("Size of the packet: " << pkt->GetSize());
//        NS_LOG_INFO("Serialized size of the packet: " << pkt->GetSerializedSize());
//        NS_LOG_INFO("Encoder Buffer Size: " << m_encoderBuffer.size());
//        NS_LOG_INFO("Encoder Payload Size: " << m_encoder.payload_size ());
//        for(int i=0; i<(int)m_encoderBuffer.size(); i++)
//            NS_LOG_INFO("Buffer[" << i << "]: " << (uint32_t)m_encoderBuffer[i]);
      
        // Initialize transmission count
        m_transmissionCount = 0;
    }

    FWUpgradeSink::~FWUpgradeSink(){
        NS_LOG_FUNCTION (this);
        m_UDPsocket = 0;
        m_UDPsocket6 = 0;
        
        if(m_mode == 4)
            PrintStatsMode4();
        else if(m_mode == 6)
            PrintStatsMode6();
        else if(m_mode == 8)
            PrintStatsMode8();
        else
            PrintStats();
    }

    uint32_t FWUpgradeSink::GetTotalRx () const{
        NS_LOG_FUNCTION (this);
        return m_totalRx;
    }

    Ptr<Socket> FWUpgradeSink::GetListeningSocket (void) const{
        NS_LOG_FUNCTION (this);
        return m_socket;
    }

    std::list<Ptr<Socket> > FWUpgradeSink::GetAcceptedSockets (void) const{
        NS_LOG_FUNCTION (this);
        return m_socketList;
    }
    
    void FWUpgradeSink::SetTargetedSMAddress (Address address){
        NS_LOG_FUNCTION (this << address);
        
        m_targetedSMAddressList.push_back(address);
    }
    Address FWUpgradeSink::GetTargetedSMAddress (uint32_t index){
        NS_LOG_FUNCTION (this << index);
        
        return m_targetedSMAddressList[index];
    }

    void FWUpgradeSink::DoDispose (void){
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
    void FWUpgradeSink::StartApplication (){ // Called at time specified by Start
        NS_LOG_FUNCTION (this);

        if(m_mode == 0 || m_mode == 3){ // The mode in which the gateway broadcasts a FWUReq message
            // A socket for listening the ACK messages sent by the SMs that have received a FWUReq
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKsocket){
                m_ACKsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 1024);
                m_ACKsocket->Bind (local);
                
                if (addressUtils::IsMulticast (m_localAddress)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_ACKsocket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_localAddress);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            
            m_ACKsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACK, this));
            m_ACKsocket->SetAllowBroadcast (true);
            
            // A socket for broadcasting the FWUReq message
            if (!m_UDPsocket){
                m_UDPsocket = Socket::CreateSocket (GetNode (), tid);

                m_peerAddress = Ipv4Address ("10.1.1.255");
                m_peerPort = 2048;

                if (Ipv4Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (Ipv6Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (InetSocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else if (Inet6SocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }

            m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_UDPsocket->SetAllowBroadcast (true);
            if(m_mode == 0)
                m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode0, this);
            else m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode3, this);
        }
        else if(m_mode == 1){ // The mode in which the gateway unicasts a FWUReq message to the targeted SMs
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            m_targetedSMSockets = (Ptr<Socket> *)calloc(m_nTargetedSMs, sizeof(Ptr<Socket>));
            
            // The sockets to the targeted SMs
            for(int i = 0; i<(int)m_nTargetedSMs; i++) {
                if (!m_targetedSMSockets[i]){
                    m_targetedSMSockets[i] = Socket::CreateSocket (GetNode (), tid);
                    
                    if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i]) || 
                            PacketSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                        m_targetedSMSockets[i]->Bind ();
                        m_targetedSMSockets[i]->Connect (m_targetedSMAddressList[i]);
                    }
                    else{
                        NS_ASSERT_MSG (false, "Incompatible address type: " << m_targetedSMAddressList[i]);
                    }
                }
                m_targetedSMSockets[i]->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
                m_targetedSMSockets[i]->SetAllowBroadcast (true);
            }
            
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode1, this);
        }
        else if(m_mode == 2){ // The mode in which the gateway initiates a flood with a FWUReq message to its child SMs
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            m_targetedSMSockets = (Ptr<Socket> *)calloc(m_nChildSMs, sizeof(Ptr<Socket>));
            
            // The sockets to the child SMs
            for(int i = 0; i<(int)m_nChildSMs; i++) {
                if (!m_targetedSMSockets[i]){
                    m_targetedSMSockets[i] = Socket::CreateSocket (GetNode (), tid);
                    
                    if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i]) || 
                            PacketSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                        m_targetedSMSockets[i]->Bind ();
                        m_targetedSMSockets[i]->Connect (m_targetedSMAddressList[i]);
                    }
                    else{
                        NS_ASSERT_MSG (false, "Incompatible address type: " << m_targetedSMAddressList[i]);
                    }
                }
                m_targetedSMSockets[i]->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
                m_targetedSMSockets[i]->SetAllowBroadcast (true);
            }
            
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode2, this);
        }
        else if(m_mode == 4){ // The mode in which the gateway broadcasts a FWUReq message
            // A socket for listening the ACK messages sent by the SMs that have received a FWUReq
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKsocket){
                m_ACKsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 1024);
                m_ACKsocket->Bind (local);
                
                if (addressUtils::IsMulticast (m_localAddress)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_ACKsocket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_localAddress);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_ACKsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKMode4, this));
            m_ACKsocket->SetAllowBroadcast (true);
            
            if(!m_localTCPsocket){  // A socket for listening the FTP packets
                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);

                m_localTCPsocket->Bind (m_local);
                m_localTCPsocket->Listen ();
                m_localTCPsocket->SetAcceptCallback (
                    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                    MakeCallback (&FWUpgradeSink::HandleAcceptMode4, this));
                m_localTCPsocket->SetCloseCallbacks (
                    MakeCallback (&FWUpgradeSink::HandlePeerClose, this),
                    MakeCallback (&FWUpgradeSink::HandlePeerError, this));

                m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadMode4, this));
            }
            
            // A socket for broadcasting the FWUReq message
            if (!m_UDPsocket){
                m_UDPsocket = Socket::CreateSocket (GetNode (), tid);

                m_peerAddress = Ipv4Address ("10.1.1.255");
                m_peerPort = 2048;

                if (Ipv4Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (Ipv6Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (InetSocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else if (Inet6SocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_UDPsocket->SetAllowBroadcast (true);
            m_sendEvent = Simulator::ScheduleNow(&FWUpgradeSink::SendMode4, this);
        }
        else if(m_mode == 5){ // The mode in which the gateway unicasts the signcrypted FWUF to the targeted SMs
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            
            if(!m_ACKsocket){
                m_ACKsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 1024);
                m_ACKsocket->Bind (local);
                
                if (addressUtils::IsMulticast (m_localAddress)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_ACKsocket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_localAddress);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_ACKsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKMode5, this));
            m_ACKsocket->SetAllowBroadcast (true);
            
            m_targetedSMSockets = (Ptr<Socket> *)calloc(m_nTargetedSMs, sizeof(Ptr<Socket>));
            // The sockets to the targeted SMs
            for(int i = 0; i<(int)m_nTargetedSMs; i++) {
                if (!m_targetedSMSockets[i]){
                    m_targetedSMSockets[i] = Socket::CreateSocket (GetNode (), tid);
                    
                    if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i]) || 
                            PacketSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                        m_targetedSMSockets[i]->Bind ();
                        m_targetedSMSockets[i]->Connect (m_targetedSMAddressList[i]);
                    }
                    else{
                        NS_ASSERT_MSG (false, "Incompatible address type: " << m_targetedSMAddressList[i]);
                    }
                }
                m_targetedSMSockets[i]->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
                m_targetedSMSockets[i]->SetAllowBroadcast (true);
            }
            
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode5, this);
        }
        else if(m_mode == 6){ // The mode in which the gateway unicasts a signed FWU Request to the targeted SMs
            if(!m_localTCPsocket){  // A socket for listening the FTP packets
                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);

                m_localTCPsocket->Bind (m_local);
                m_localTCPsocket->Listen ();
                m_localTCPsocket->SetAcceptCallback (
                    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                    MakeCallback (&FWUpgradeSink::HandleAcceptACKandFTP, this));
                m_localTCPsocket->SetCloseCallbacks (
                    MakeCallback (&FWUpgradeSink::HandlePeerClose, this),
                    MakeCallback (&FWUpgradeSink::HandlePeerError, this));

                m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKandFTP, this));
            }
            
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            m_targetedSMSockets = (Ptr<Socket> *)calloc(m_nTargetedSMs, sizeof(Ptr<Socket>));
            // The sockets to the targeted SMs
            for(int i = 0; i<(int)m_nTargetedSMs; i++) {
                if (!m_targetedSMSockets[i]){
                    m_targetedSMSockets[i] = Socket::CreateSocket (GetNode (), tid);
                    
                    if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i]) || 
                            PacketSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                        m_targetedSMSockets[i]->Bind ();
                        m_targetedSMSockets[i]->Connect (m_targetedSMAddressList[i]);
                    }
                    else{
                        NS_ASSERT_MSG (false, "Incompatible address type: " << m_targetedSMAddressList[i]);
                    }
                }
                m_targetedSMSockets[i]->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
                m_targetedSMSockets[i]->SetAllowBroadcast (true);
            }
            
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode6, this);
        }
        else if(m_mode == 7){ // The mode in which the gateway broadcasts the FWUF in encoded batches
            // A socket for listening the ACK messages sent by the SMs that have decoded a batch of the FWUF
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKsocket){
                m_ACKsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 1024);
                m_ACKsocket->Bind (local);
                
                if (addressUtils::IsMulticast (m_localAddress)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_ACKsocket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_localAddress);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            
            m_ACKsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKMode7, this));
            m_ACKsocket->SetAllowBroadcast (true);
            
            // A socket for broadcasting the encoded packet of each batch of the FWUF
            if (!m_UDPsocket){
                m_UDPsocket = Socket::CreateSocket (GetNode (), tid);

                m_peerAddress = Ipv4Address ("10.1.1.255");
                m_peerPort = 2048;

                if (Ipv4Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (Ipv6Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (InetSocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else if (Inet6SocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }

            m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_UDPsocket->SetAllowBroadcast (true);
            
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode7, this);
        }
        else if(m_mode == 8){ // The mode in which the gateway broadcasts a FWUReq message using network coding
            // A socket for listening the ACK messages sent by the SMs that have received a FWUReq
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKsocket){
                m_ACKsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 1024);
                m_ACKsocket->Bind (local);
                
                if (addressUtils::IsMulticast (m_localAddress)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_ACKsocket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_localAddress);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_ACKsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKMode8, this));
            m_ACKsocket->SetAllowBroadcast (true);
            
            if(!m_localTCPsocket){  // A socket for listening the FTP packets
                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);

                m_localTCPsocket->Bind (m_local);
                m_localTCPsocket->Listen ();
                m_localTCPsocket->SetAcceptCallback (
                    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                    MakeCallback (&FWUpgradeSink::HandleAcceptTCPMode8, this));
                m_localTCPsocket->SetCloseCallbacks (
                    MakeCallback (&FWUpgradeSink::HandlePeerClose, this),
                    MakeCallback (&FWUpgradeSink::HandlePeerError, this));

                m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleFTPMode8, this));
            }
            
            // A socket for broadcasting the FWUReq message
            if (!m_UDPsocket){
                m_UDPsocket = Socket::CreateSocket (GetNode (), tid);

                m_peerAddress = Ipv4Address ("10.1.1.255");
                m_peerPort = 2048;

                if (Ipv4Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (Ipv6Address::IsMatchingType(m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
                }
                else if (InetSocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else if (Inet6SocketAddress::IsMatchingType (m_peerAddress) == true){
                    m_UDPsocket->Bind6 ();
                    m_UDPsocket->Connect (m_peerAddress);
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_UDPsocket->SetAllowBroadcast (true);
            m_sendEvent = Simulator::ScheduleNow (&FWUpgradeSink::SendMode8, this);            
        }
        else
            NS_LOG_ERROR("We have a problem with the mode: " << m_mode);
////////////////////////////////////UDP/////////////////////////////////////////
        
  
//        if (m_UDPsocket == 0){
//            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
//            m_UDPsocket = Socket::CreateSocket (GetNode (), tid);
//            InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), m_UDPPort);
//            m_UDPsocket->Bind (local);
//            
//            if (addressUtils::IsMulticast (m_UDPlocal)){
//                Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_UDPsocket);
//                if (udpSocket){
//                    // equivalent to setsockopt (MCAST_JOIN_GROUP)
//                    udpSocket->MulticastJoinGroup (0, m_UDPlocal);
//                }
//                else
//                    NS_FATAL_ERROR ("Error: Failed to join multicast group");
//            }
//        }
//
//        if (m_UDPsocket6 == 0){
//            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
//            m_UDPsocket6 = Socket::CreateSocket (GetNode (), tid);
//            Inet6SocketAddress local6 = Inet6SocketAddress (Ipv6Address::GetAny (), m_UDPPort);
//            m_UDPsocket6->Bind (local6);
//            
//            if (addressUtils::IsMulticast (local6)){
//                Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_UDPsocket6);
//                if (udpSocket){
//                    // equivalent to setsockopt (MCAST_JOIN_GROUP)
//                    udpSocket->MulticastJoinGroup (0, local6);
//                }
//                else
//                    NS_FATAL_ERROR ("Error: Failed to join multicast group");
//            }
//        }
//
//        m_UDPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadUDP, this));
//        m_UDPsocket6->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadUDP, this));

////////////////////////////////////TCP/////////////////////////////////////////

//        //[0]->GW, [1]->AGG, [2]->LEAF
//
//        // Create the socket if not already
//        //GW
//        if(!m_localTCPsocket){  // A socket for listening the challenge sent by the SMs
//            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
//            m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);
//            
//            m_localTCPsocket->Bind (m_local);
//            m_localTCPsocket->Listen ();
//            m_localTCPsocket->ShutdownSend ();
//            m_localTCPsocket->SetAcceptCallback (
//                MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
//                MakeCallback (&FWUpgradeSink::HandleAccept, this));
//            m_localTCPsocket->SetCloseCallbacks (
//                MakeCallback (&FWUpgradeSink::HandlePeerClose, this),
//                MakeCallback (&FWUpgradeSink::HandlePeerError, this));
//
//            m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadTCP, this));
//        }
        
//        else if(m_meterType == (uint32_t)2){    //meshToEV Meter
//            if (!m_socket){
//                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
//                m_socket = Socket::CreateSocket (GetNode (), tid);
//
//                if (Inet6SocketAddress::IsMatchingType (m_target)){
//                    m_socket->Bind6 ();
//                }
//                else if (InetSocketAddress::IsMatchingType (m_target) ||
//                 PacketSocketAddress::IsMatchingType (m_target)){
//                    m_socket->Bind ();
//                }
//
//                m_socket->Connect (m_target);
//                m_socket->SetAllowBroadcast (true);
//                //            m_socket->ShutdownRecv ();
//
//                m_socket->SetConnectCallback (
//                            MakeCallback (&FWUpgradeSink::ConnectionSucceeded, this),
//                            MakeCallback (&FWUpgradeSink::ConnectionFailed, this));
//
//                m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadTCP, this));
//            }
//        }
        m_nodeId = GetNode()->GetId();
    }
    
    void FWUpgradeSink::PrintStatsMode4(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
            double activeTimePeriod;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;
                
                NS_LOG_DEBUG("XxX Sink XxX: GATEWAY: Total Delay = " << totDelay << 
                        " ms Total Bytes = " << totBytes << " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
            activeTimePeriod = m_activeTP; //(m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("XxX Sink XxX: GATEWAY: Active Time Period = " << activeTimePeriod << " s");
            
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            double completionTime = (m_completionTS.ToInteger(Time::US) - 
                                     m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("CcC Sink CcC: GATEWAY: Av. EtoE-Delay = " << avEtoEDelay << 
                        " s Completion Time = " << completionTime << " s NoNTargeted Throughput = " << 
                        throughput << " kbps");
        }
    }
    
    void FWUpgradeSink::PrintStatsMode6(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
            double activeTimePeriod;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;
                
                NS_LOG_DEBUG("XxX Sink XxX: GATEWAY: Total Delay = " << totDelay << 
                        " ms Total Bytes = " << totBytes << " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
            activeTimePeriod = m_activeTP;
            //(m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - m_unicasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("XxX Sink XxX: GATEWAY: Active Time Period = " << activeTimePeriod << " s");
            
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            double completionTime = (m_completionTS.ToInteger(Time::US) - 
                                     m_unicasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("CcC Sink CcC: GATEWAY: Av. EtoE-Delay = " << avEtoEDelay << 
                        " s Completion Time = " << completionTime << " s NoNTargeted Throughput = " << 
                        throughput << " kbps");
        }
    }
    
    void FWUpgradeSink::PrintStatsMode8(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
            double activeTimePeriod;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;
                
                NS_LOG_DEBUG("XxX Sink XxX: GATEWAY: Total Delay = " << totDelay << 
                        " ms Total Bytes = " << totBytes << " bytes.");
            }
            
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
            activeTimePeriod = (m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - 
                                  m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("XxX Sink XxX: GATEWAY: Active Time Period = " << activeTimePeriod << " s");
            
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            double completionTime = (m_completionTS.ToInteger(Time::US) - 
                                     m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("CcC Sink CcC: GATEWAY: Av. EtoE-Delay = " << avEtoEDelay << 
                    " s Completion Time = " << completionTime << " s Throughput = " << throughput << " kbps");
        }
    }
    
    void FWUpgradeSink::PrintStats(){
        NS_LOG_FUNCTION(this);
        //m_unicasts
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
//            Time firstRx;
//            Time lastRx;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
            double activeTimePeriod;
//            double delta = 0.0;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;
                
                NS_LOG_DEBUG("XxX Sink XxX: GATEWAY: Total Delay = " << totDelay << 
                        " ms Total Bytes = " << totBytes << " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
//            delta = (lastRx.ToInteger (Time::US) - firstRx.ToInteger (Time::US))/1000000.0;
            
            double completionTime;
            if(m_mode == 0){
//                delta = (lastRx.ToInteger(Time::US) - 
//                    m_initialBroadcast.minTxTime.ToInteger(Time::US))/1000000.0;
            }
            else if(m_mode == 1 || m_mode == 2 || m_mode == 5 || m_mode == 6){
//                delta = (lastRx.ToInteger(Time::US) - 
//                    m_unicasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            }
            else if(m_mode == 4){
//                delta = (lastRx.ToInteger(Time::US) - 
//                        m_initialBroadcast.minTxTime.ToInteger(Time::US))/1000000.0;
            }
            else if(m_mode == 7){
                activeTimePeriod = (m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - 
                                      m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
                completionTime = (m_completionTS.ToInteger(Time::US) - 
                                  m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
//                delta = (lastRx.ToInteger(Time::US) - m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            }
            else if(m_mode == 8){
                activeTimePeriod = (m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - 
                                      m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
                completionTime = (m_completionTS.ToInteger(Time::US) - 
                                  m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
//                delta = (lastRx.ToInteger(Time::US) - m_broadcasts[0].minTxTime.ToInteger(Time::US))/1000000.0;
            }
            else
                NS_LOG_ERROR("We have a problem with the mode!!!");
            
            NS_LOG_INFO("XxX Sink XxX: GATEWAY: Active Time Period = " << activeTimePeriod << " s");
            
//            NS_LOG_INFO("Delta = " << delta);
            
//            throughput = ((totBytes*8)/1024)/delta;
//            throughput = ((totBytes*8)/1024.0)/m_activeTP;
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
//            completionTime = delta; // + (m_procDelay/1000000000.0);
//            double SR = m_rxCount/m_nTargetedSMs;
            
            NS_LOG_INFO("CcC Sink CcC: GATEWAY: Av. EtoE-Delay = " << avEtoEDelay << 
                    " s Completion Time = " << completionTime << " s Throughput = " << 
                    throughput << " kbps");
//            Success Rate = " << SR*100 <<
        }
    }

    void FWUpgradeSink::StopApplication (){     // Called at time specified by Stop
        NS_LOG_FUNCTION (this);
        while(!m_socketList.empty ()){ //these are accepted sockets, close them
            Ptr<Socket> acceptedSocket = m_socketList.front ();
            m_socketList.pop_front ();
            acceptedSocket->Close ();
        }
        
        while(!m_targetSockets.empty()){
            Ptr<Socket> targetSocket = m_targetSockets.front();
            m_targetSockets.pop_front();
            targetSocket->Close();
        }
        
        if (m_socket){
            m_socket->Close ();
            m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
        }

        CancelEvents ();
        
        if(m_targetSocket != 0)
            m_targetSocket->Close ();
        else
            NS_LOG_WARN ("VanetPacketSink found null socket to close in StopApplication");

        ///////////////////////////////UDP////////////////////////////////////
        if (m_UDPsocket != 0) {
            m_UDPsocket->Close ();
            m_UDPsocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
        }
    }

    void FWUpgradeSink::CancelEvents (){
        NS_LOG_FUNCTION (this);

        if (m_sendEvent.IsRunning ()){ 
            // Cancel the pending send packet event
            // Calculate residual bits since last packet sent
            Time delta (Simulator::Now () - m_lastStartTime);
        }
        
        Simulator::Cancel (m_sendEvent);
        Simulator::Cancel (m_alarmEvent);
        Simulator::Cancel (m_reTXEvent);
    }
    
    void FWUpgradeSink::HandleACK (Ptr<Socket> socket){
        NS_LOG_FUNCTION(this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            if(seqNum == 4000){
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("The GATEWAY has received an ACK sent at " << txtime.GetSeconds() << " in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            now.GetSeconds () << " s");
                }
                
                m_rxCount += 1.0;
                
                StatRecord tmp;
                tmp.round = seqNum;
                tmp.rxCount = 1;
                tmp.rxBytes = m_rxBytes;
                tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
                tmp.firstRxTime = now;
                tmp.lastRxTime = now;
                tmp.minTxTime = txtime;
                m_stat.push_back(tmp);

                uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
                IPTSMap::iterator itSeq;
                itSeq = m_IpTimeStampMap.find(hostOrderIpAddress);

                if(itSeq == m_IpTimeStampMap.end()){
                    m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                    m_nRecACKs++;
                }
                
                if(m_nRecACKs == (m_nSMs-1)){
                    NS_LOG_INFO("The GATEWAY has received all ACKs!!!");
                    if(m_mode == 0 || m_mode == 3){
                        Simulator::Cancel (m_alarmEvent);
                        Simulator::Cancel (m_reTXEvent);
                        if(m_mode == 3)
                            StopApplication();
                    }
                    else if(m_mode == 4){
                        Simulator::Cancel (m_alarmEvent);
                    }
//                    Simulator::Cancel (m_reTXEvent);
                }
            }
        }
    }
    
    void FWUpgradeSink::HandleACKMode4 (Ptr<Socket> socket){
        NS_LOG_FUNCTION(this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            m_rxCount += 1.0;
                
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("The GATEWAY has received an ACK sent at " << txtime.GetSeconds() << " in size of " << 
                        m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                        ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                        now.GetSeconds () << " s");
            }

            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();

            IPTSMap::iterator itSeq;
            itSeq = m_IpTimeStampMap.find(hostOrderIpAddress);

            if(itSeq == m_IpTimeStampMap.end()){
                m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                m_nRecACKs++;
            }

            if(m_nRecACKs == (m_nSMs-1)){
                Simulator::Cancel (m_alarmEvent);
                NS_LOG_INFO("The GATEWAY has received all ACKs!!!");
            }
        }
    }
    
    void FWUpgradeSink::HandleACKMode5 (Ptr<Socket> socket){
        NS_LOG_FUNCTION(this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            m_rxCount += 1.0;
                
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if(seqNum == 4000){
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("The GATEWAY has received an ACK sent at " << txtime.GetSeconds() << " in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            now.GetSeconds () << " s");
                }
                
                uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
                IPEventIdMap::iterator iterator;
                iterator = m_IpEventIdMap.find(hostOrderIpAddress);

                if(iterator != m_IpEventIdMap.end()){
                    EventId eventId = iterator->second;
                    Simulator::Cancel (eventId);
                    NS_LOG_INFO("Event " << eventId.GetUid() << " was canceled!!!");
                }
                else NS_LOG_INFO("We have a problem with Ip-Event map!!!");
            }
        }
    }
    
    void FWUpgradeSink::HandleACKMode7 (Ptr<Socket> socket){
        NS_LOG_FUNCTION(this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            m_rxCount += 1.0;
                
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if(seqNum >= 4000){
                uint32_t batchIndex = seqNum - 4000;
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("The GATEWAY has received an ACK[" << (seqNum-4000) << "] sent at " << 
                            txtime.GetSeconds() << " in size of " << m_rxBytes << " bytes from " << 
                            InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" << 
                            InetSocketAddress::ConvertFrom (from).GetPort () << " at " << now.GetSeconds () << " s");
                }
                
                uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
                IPTSMap::iterator iterator;
                iterator = m_IpTimeStampMaps[batchIndex].find(hostOrderIpAddress);

                if(iterator == m_IpTimeStampMaps[batchIndex].end()){
                    m_IpTimeStampMaps[batchIndex].insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                    m_nRecACKs++;
                }
                
                if(m_nRecACKs == (m_nSMs-1)){
                    Simulator::Cancel(m_sendEvent);
                    m_nRecACKs = 0;
                    m_batchCounter++;
//                        m_IpTimeStampMaps[batchIndex].clear();

                    if(m_batchCounter < m_nBatches)
                        m_sendEvent = Simulator::ScheduleNow(&FWUpgradeSink::SendMode7, this);
                    else{
                        m_completionTS = Simulator::Now();
                        StopApplication();
                    }
                }
            }
        }
    }
    
    void FWUpgradeSink::HandleACKMode8 (Ptr<Socket> socket){
        NS_LOG_FUNCTION(this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            m_rxCount += 1.0;
                
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if(seqNum == 4000){
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("The GATEWAY has received an ACK sent at " << txtime.GetSeconds() << " in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            now.GetSeconds () << " s");
                }
                
                uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
                IPTSMap::iterator itSeq;
                itSeq = m_IpTimeStampMap.find(hostOrderIpAddress);

                if(itSeq == m_IpTimeStampMap.end()){
                    m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                    m_nRecACKs++;
                }
                
                if(m_nRecACKs == (m_nSMs-1)){
                    Simulator::Cancel(m_sendEvent);
                    NS_LOG_INFO("The GATEWAY has successfully received all ACKs!!!");
                }
            }
        }
    }
    
    void FWUpgradeSink::SendMode0 (void){
        NS_LOG_FUNCTION (this);

//        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(1000);
//        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
//        packet->AddHeader(header);
        
        std::cout << "+----------------------+" << std::endl;
        std::cout << "|Sending a coded packet|" << std::endl;
        std::cout << "+----------------------+" << std::endl;
        
        uint32_t bytesUsed = m_encoder.write_payload (&m_payload[0]);
        NS_LOG_INFO("Bytes used: " << bytesUsed);
        for(int i=0; i<(int)bytesUsed; i++)
            NS_LOG_INFO("Payload[" << i << "]: " << (char)m_payload[i]);
        packet = Create<Packet> (&m_payload[0], bytesUsed);
        packet->AddHeader(header);
        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        m_transmissionCount++;
        
        NS_LOG_INFO("Transmission Counter = " << m_transmissionCount);

//        if(m_transmissionCount%m_generationSize != 0)
            m_reTXEvent = Simulator::Schedule (Seconds(3.0), &FWUpgradeSink::SendMode0, this);
//        else
//            m_reTXEvent = Simulator::Schedule (Seconds(5.0), &FWUpgradeSink::SendMode0, this);
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
//        m_txTrace (packet);
//        m_UDPsocket->Send (packet);
//        
//        m_alarmEvent = Simulator::Schedule(NanoSeconds (5000414800), &FWUpgradeSink::Alarm, this);  // 5 seconds + time for signing a 48-byte message

        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The GATEWAY (Node " << GetNode()->GetId() << ") broadcasted a Firmware Upgrade Request in "
                    "size of " << packet->GetSize() << " bytes to " << Ipv4Address::ConvertFrom (m_peerAddress) << 
                    ":" << m_peerPort << " at " << Simulator::Now ().GetSeconds () << " s");
        }
//        else if (Ipv6Address::IsMatchingType (m_peerAddress)){
//            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s GW (Node " << 
//            GetNode()->GetId() << ") sent 32 bytes to " <<
//            Ipv6Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);
//        }
        
        m_initialBroadcast.round = header.GetSeq();
        m_initialBroadcast.rxCount = 0;
        m_initialBroadcast.rxBytes = packet->GetSize();
        m_initialBroadcast.totDelay = 0;
        m_initialBroadcast.firstRxTime = Simulator::Now();
        m_initialBroadcast.lastRxTime = Simulator::Now();
        m_initialBroadcast.minTxTime = header.GetTs();
    }
    
    void FWUpgradeSink::SendMode1 (void){
        NS_LOG_FUNCTION (this);
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (packet);
        
        for(int i = 0; i<(int)m_nTargetedSMs; i++) {
            m_targetedSMSockets[i]->Send (packet);
            
            if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                        ") unicasted a Firmware Upgrade Request in size of " << 
                        packet->GetSize() << " bytes to " << 
                        InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4() << 
                        ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetPort() << 
                        " at " << Simulator::Now ().GetSeconds () << " s");
            }
            
            StatRecord tmp;
            tmp.round = header.GetSeq();
            tmp.rxCount = 0;
            tmp.rxBytes = packet->GetSize();
            tmp.totDelay = 0;
            tmp.firstRxTime = Simulator::Now();
            tmp.lastRxTime = Simulator::Now();
            tmp.minTxTime = header.GetTs();
            m_unicasts.push_back(tmp);
        }
    }
    
    void FWUpgradeSink::SendMode2 (void){
        NS_LOG_FUNCTION (this);
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (packet);
        
        for(int i = 0; i<(int)m_nChildSMs; i++) {
            m_targetedSMSockets[i]->Send (packet);
            
            if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                        ") unicasted a Firmware Upgrade Request in size of " << 
                        packet->GetSize() << " bytes to " << 
                        InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4() << 
                        ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetPort() << 
                        " at " << Simulator::Now ().GetSeconds () << " s");
            }
            
            StatRecord tmp;
            tmp.round = header.GetSeq();
            tmp.rxCount = 0;
            tmp.rxBytes = packet->GetSize();
            tmp.totDelay = 0;
            tmp.firstRxTime = Simulator::Now();
            tmp.lastRxTime = Simulator::Now();
            tmp.minTxTime = header.GetTs();
            m_unicasts.push_back(tmp);
        }

//        else if (Ipv6Address::IsMatchingType (m_peerAddress)){
//            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s GW (Node " << 
//            GetNode()->GetId() << ") sent 32 bytes to " <<
//            Ipv6Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);
//        }
    }
    
    void FWUpgradeSink::SendMode3 (void){
        NS_LOG_FUNCTION (this);
        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);

        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        m_transmissionCount++;
        
        NS_LOG_INFO("Transmission Counter = " << m_transmissionCount);
        
        m_alarmEvent = Simulator::Schedule(NanoSeconds (5000414800), &FWUpgradeSink::Alarm, this);  // 5 seconds + time for signing a 48-byte message

        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The GATEWAY (Node " << GetNode()->GetId() << ") broadcasted the FWUF in size of " << 
                    packet->GetSize() << " bytes to " << Ipv4Address::ConvertFrom (m_peerAddress) << 
                    ":" << m_peerPort << " at " << Simulator::Now ().GetSeconds () << " s");
        }
        
        m_initialBroadcast.round = header.GetSeq();
        m_initialBroadcast.rxCount = 0;
        m_initialBroadcast.rxBytes = packet->GetSize();
        m_initialBroadcast.totDelay = 0;
        m_initialBroadcast.firstRxTime = Simulator::Now();
        m_initialBroadcast.lastRxTime = Simulator::Now();
        m_initialBroadcast.minTxTime = header.GetTs();
    }
    
    void FWUpgradeSink::SendMode4 (void){
        NS_LOG_FUNCTION (this);
        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);

        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        m_transmissionCount++;
        
        StatRecord tmp;
        tmp.round = header.GetSeq();
        tmp.rxCount = 1000;
        tmp.rxBytes = packet->GetSize();
        tmp.totDelay = 0;
        tmp.firstRxTime = Simulator::Now();
        tmp.lastRxTime = Simulator::Now();
        tmp.minTxTime = header.GetTs();
        m_broadcasts.push_back(tmp);
        
        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The GATEWAY (Node " << GetNode()->GetId() << ") broadcasted a FWU Request in size of " << 
                    packet->GetSize() << " bytes to " << Ipv4Address::ConvertFrom (m_peerAddress) << 
                    ":" << m_peerPort << " at " << Simulator::Now ().GetSeconds () << " s");
        }
        
        NS_LOG_INFO("Transmission Counter = " << m_transmissionCount);
        
        m_alarmEvent = Simulator::Schedule(NanoSeconds (5000430500), &FWUpgradeSink::Alarm, this);  // 5 seconds + time for signing a 12-byte message
    }
    
    void FWUpgradeSink::SendMode5 (void){
        NS_LOG_FUNCTION (this);
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (packet);
        
        for(int i = 0; i<(int)m_nTargetedSMs; i++) {
            m_targetedSMSockets[i]->Send (packet);
            
            if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                        ") unicasted the FWUF in size of " << 
                        packet->GetSize() << " bytes to " << 
                        InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4() << 
                        ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetPort() << 
                        " at " << Simulator::Now ().GetSeconds () << " s");
            }
            
            StatRecord tmp;
            tmp.round = header.GetSeq();
            tmp.rxCount = 0;
            tmp.rxBytes = packet->GetSize();
            tmp.totDelay = 0;
            tmp.firstRxTime = Simulator::Now();
            tmp.lastRxTime = Simulator::Now();
            tmp.minTxTime = header.GetTs();
            m_unicasts.push_back(tmp);
            
            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4 ().Get();
            IPEventIdMap::iterator iterator;
            iterator = m_IpEventIdMap.find(hostOrderIpAddress);

            if(iterator == m_IpEventIdMap.end()){
                EventId eventId = Simulator::Schedule(Seconds(5.0), &FWUpgradeSink::ReTX, this, m_targetedSMSockets[i], packet, i);
                m_IpEventIdMap.insert(std::make_pair(hostOrderIpAddress, eventId));
                NS_LOG_INFO("Event " << eventId.GetUid() << " was scheduled!!!");
            }
            else NS_LOG_INFO("We have a problem with Ip-Event map!!!");
        }
    }
    
    void FWUpgradeSink::SendMode6 (void){
        NS_LOG_FUNCTION (this);
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(1000);
        packet = Create<Packet> (m_REQSignatureSize-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (packet);
        
        for(int i = 0; i<(int)m_nTargetedSMs; i++) {
            m_targetedSMSockets[i]->Send (packet);
            
            if (InetSocketAddress::IsMatchingType (m_targetedSMAddressList[i])){
                NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                        ") unicasted an FWU Request in size of " << 
                        packet->GetSize() << " bytes to " << 
                        InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4() << 
                        ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetPort() << 
                        " at " << Simulator::Now ().GetSeconds () << " s");
            }
            
            StatRecord tmp;
            tmp.round = header.GetSeq();
            tmp.rxCount = 0;
            tmp.rxBytes = packet->GetSize();
            tmp.totDelay = 0;
            tmp.firstRxTime = Simulator::Now();
            tmp.lastRxTime = Simulator::Now();
            tmp.minTxTime = header.GetTs();
            m_unicasts.push_back(tmp);
            
            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4 ().Get();
            IPEventIdMap::iterator iterator;
            iterator = m_IpEventIdMap.find(hostOrderIpAddress);

            if(iterator == m_IpEventIdMap.end()){
                EventId eventId = Simulator::Schedule(NanoSeconds(5000430500), &FWUpgradeSink::ReTX, this, m_targetedSMSockets[i], packet, i);
                m_IpEventIdMap.insert(std::make_pair(hostOrderIpAddress, eventId));
                NS_LOG_INFO("Event " << eventId.GetUid() << " was scheduled!!!");
            }
            else NS_LOG_INFO("We have a problem with Ip-Event map!!!");
        }
    }
    
    void FWUpgradeSink::SendMode7 (void){
        NS_LOG_FUNCTION (this);

        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;

        header.SetSeq(1000+m_batchCounter);
        
        std::cout << "+----------------------+" << std::endl;
        std::cout << "|Sending a coded packet|" << std::endl;
        std::cout << "+----------------------+" << std::endl;

        uint32_t bytesUsed = m_encoders[m_batchCounter].write_payload (&m_payloads[m_batchCounter][0]);

        packet = Create<Packet> (&m_payloads[m_batchCounter][0], bytesUsed);
        packet->AddHeader(header);
        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        m_transmissionCount++;
        
        NS_LOG_INFO("Transmission Counter = " << m_transmissionCount);

//        if(m_transmissionCount%m_generationSize != 0)
            m_sendEvent = Simulator::Schedule (Seconds(2.0), &FWUpgradeSink::SendMode7, this);
//            m_sendEvent = Simulator::Schedule (Seconds(2.0), &FWUpgradeSink::SendMode7, this);
//            m_sendEvent = Simulator::Schedule (Seconds(3.0), &FWUpgradeSink::SendMode7, this);
//        else
//            m_sendEvent = Simulator::Schedule (Seconds(5.0), &FWUpgradeSink::SendMode7, this);
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
//        m_txTrace (packet);
//        m_UDPsocket->Send (packet);
//        
//        m_alarmEvent = Simulator::Schedule(NanoSeconds (5000414800), &FWUpgradeSink::Alarm, this);  // 5 seconds + time for signing a 48-byte message

        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The GATEWAY (Node " << GetNode()->GetId() << ") broadcasted an encoded packet of batch #" << 
                    m_batchCounter <<  " in the FWUF in size of " << packet->GetSize() << " bytes to " << 
                    Ipv4Address::ConvertFrom (m_peerAddress) << ":" << m_peerPort << " at " << 
                    Simulator::Now ().GetSeconds () << " s");
        }
//        else if (Ipv6Address::IsMatchingType (m_peerAddress)){
//            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s GW (Node " << 
//            GetNode()->GetId() << ") sent 32 bytes to " <<
//            Ipv6Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);
//        }
        
        StatRecord tmp;
        tmp.round = header.GetSeq();
        tmp.rxCount = 0;
        tmp.rxBytes = packet->GetSize();
        tmp.totDelay = 0;
        tmp.firstRxTime = Simulator::Now();
        tmp.lastRxTime = Simulator::Now();
        tmp.minTxTime = header.GetTs();
        m_broadcasts.push_back(tmp);
    }
    
    void FWUpgradeSink::SendMode8 (void){
        NS_LOG_FUNCTION (this);

        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;

        header.SetSeq(1000);
        
        std::cout << "+----------------------+" << std::endl;
        std::cout << "|Sending a coded packet|" << std::endl;
        std::cout << "+----------------------+" << std::endl;

        uint32_t bytesUsed = m_encoder.write_payload (&m_payload[0]);
        
        packet = Create<Packet> (&m_payload[0], bytesUsed);
        packet->AddHeader(header);
        
        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        m_transmissionCount++;
        
        NS_LOG_INFO("Transmission Counter = " << m_transmissionCount);

        m_sendEvent = Simulator::Schedule (Seconds(2.0), &FWUpgradeSink::SendMode8, this);

        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The GATEWAY (Node " << GetNode()->GetId() << ") broadcasted an encoded packet of batch #" << 
                    m_batchCounter <<  " in the FWUF in size of " << packet->GetSize() << " bytes to " << 
                    Ipv4Address::ConvertFrom (m_peerAddress) << ":" << m_peerPort << " at " << 
                    Simulator::Now ().GetSeconds () << " s");
        }
        
        StatRecord tmp;
        tmp.round = header.GetSeq();
        tmp.rxCount = 0;
        tmp.rxBytes = packet->GetSize();
        tmp.totDelay = 0;
        tmp.firstRxTime = Simulator::Now();
        tmp.lastRxTime = Simulator::Now();
        tmp.minTxTime = header.GetTs();
        m_broadcasts.push_back(tmp);
    }
    
    void FWUpgradeSink::ReTX(Ptr<Socket> socket, Ptr<Packet> packet, int index){
        NS_LOG_FUNCTION(this << socket << packet << index);
        SeqTsHeader header;
        packet->PeekHeader(header);
        
        m_txTrace(packet);
        socket->Send(packet);
        
        if(m_mode == 5){
            NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                            ") re-unicasted the FWUF in size of " << 
                            packet->GetSize() << " bytes to " << 
                            InetSocketAddress::ConvertFrom (m_targetedSMAddressList[index]).GetIpv4() << 
                            ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[index]).GetPort() << 
                            " at " << Simulator::Now ().GetSeconds () << " s");
        }
        else if (m_mode == 6){
            NS_LOG_INFO ("The GATEWAY (Node " << GetNode()->GetId() << 
                            ") re-unicasted the FWU Request in size of " << 
                            packet->GetSize() << " bytes to " << 
                            InetSocketAddress::ConvertFrom (m_targetedSMAddressList[index]).GetIpv4() << 
                            ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[index]).GetPort() << 
                            " at " << Simulator::Now ().GetSeconds () << " s");
        }
        
        StatRecord tmp;
        tmp.round = header.GetSeq();
        tmp.rxCount = 0;
        tmp.rxBytes = packet->GetSize();
        tmp.totDelay = 0;
        tmp.firstRxTime = Simulator::Now();
        tmp.lastRxTime = Simulator::Now();
        tmp.minTxTime = header.GetTs();
        m_unicasts.push_back(tmp);
        
        uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (m_targetedSMAddressList[index]).GetIpv4 ().Get();
                
        IPEventIdMap::iterator iterator;
        iterator = m_IpEventIdMap.find(hostOrderIpAddress);

        if(iterator != m_IpEventIdMap.end()){
            m_IpEventIdMap.erase(hostOrderIpAddress);
            EventId eventId = Simulator::Schedule(NanoSeconds(5000430500), &FWUpgradeSink::ReTX, this, socket, packet, index);
            m_IpEventIdMap.insert(std::make_pair(hostOrderIpAddress, eventId));
            NS_LOG_INFO("Event " << eventId.GetUid() << " was scheduled!!!");
        }
        else NS_LOG_INFO("We have a problem with Ip-Event map!!!");
    }
    
    void FWUpgradeSink::Alarm (void){
        NS_LOG_FUNCTION(this);
        
        NS_ASSERT (m_alarmEvent.IsExpired ());
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(5000);    //5000 -> There are some SMs that have not received the FWU Request
        packet = Create<Packet> (44-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (packet);
        m_UDPsocket->Send (packet);
        
        StatRecord tmp;
        tmp.round = header.GetSeq();
        tmp.rxCount = 5000;
        tmp.rxBytes = packet->GetSize();
        tmp.totDelay = 0;
        tmp.firstRxTime = Simulator::Now();
        tmp.lastRxTime = Simulator::Now();
        tmp.minTxTime = header.GetTs();
        m_broadcasts.push_back(tmp);
        
        m_alarmEvent = Simulator::Schedule(NanoSeconds (5000430500), &FWUpgradeSink::Alarm, this);  // 5 seconds + time for signing a 12-byte message
    }

    void FWUpgradeSink::HandleReadTCP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom (from))) {
            if (packet->GetSize () == 0) //EOF
                break;

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
//                NS_LOG_INFO("Concatenate previous stored packet and the received packet " << m_savePktSize << " " << m_pktsize );
                m_prevPacket->AddAtEnd (packet);
                m_pktsize = m_prevPacket->GetSize ();    // new pkt size from concatenation
                // delete the old record
//                NS_LOG_INFO("Delete previous stored packet ! " << from << " " << m_savePktSize);
                if (m_waitingPacket.size() > 1) {
                    std::vector<DataWaitingPacket> tmp (m_waitingPacket); // copy to temp
                    m_waitingPacket.clear();

                    for(std::vector<DataWaitingPacket>::iterator itw = tmp.begin() ; itw != tmp.end(); ++itw) {
                        if(itw->from != from) { // keep maintain in the waiting list
                            DataWaitingPacket keep;
                            keep.from = itw->from;
                            keep.pkt   = itw->pkt;
                            m_waitingPacket.push_back(keep);
//                            NS_LOG_INFO("Keep waiting packet " << keep.from << " " << keep.pkt->GetSize() << " " << m_waitingPacket.size () );
                        }
                    }
                } else m_waitingPacket.clear();
            } else m_prevPacket = packet; // there were saved packets, but none was from this address

          if (m_pktsize == m_SCH_Up) {
              HandleReport(m_prevPacket, from, socket);
          } else {
            // two cases, > and <, if higher, split them
            if (m_pktsize > m_SCH_Up) {
                uint16_t m_begin = 0;
                uint16_t m_length = m_SCH_Up;
                while (m_pktsize >= m_SCH_Up) {
    //                NS_LOG_INFO("Split packet : " << m_pktsize << " from : " << m_begin << " length " << m_length);
                    Ptr<Packet> frag = m_prevPacket->CreateFragment(m_begin, m_length);
                    HandleReport(frag, from, socket);
                    m_begin += (m_length);
                    m_pktsize -= m_SCH_Up;
                    if (m_pktsize >= m_SCH_Up) m_length = m_SCH_Up;
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
//               NS_LOG_INFO("add waiting packet " << tmp.from << " " << tmp.pkt->GetSize() << " " << m_waitingPacket.size () );               
            } // end of else m_pktsize > m_defSize
          } // end else m_pktsize == m_defSize  
      }
    }
    
    void FWUpgradeSink::HandleReadMode4 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom (from))) {
            if (packet->GetSize () == 0) //EOF
                break;
            
            Time now = Simulator::Now();
            
            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
            IPTSMap::iterator IpTsMAP;
            IpTsMAP = m_IpTimeStampMap.find(hostOrderIpAddress);

            if(IpTsMAP == m_IpTimeStampMap.end()){
                m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                m_nRecACKs++;
            }

            if(m_nRecACKs == (m_nSMs-1)){
                Simulator::Cancel (m_alarmEvent);
                NS_LOG_INFO("The GATEWAY has received all ACKs!!!");
            }

            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();

            m_rxCount += 1.0;

            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US));
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("The GATEWAY has received an FTP packet in size of " << 
                    m_rxBytes << " from " << 
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now().GetSeconds() << " s");
                
                Ptr<Packet> pack;
                SeqTsHeader header;
                if(seqNum == 0){
                    //wait for 0.5032 ms then send
                    Simulator::Schedule(NanoSeconds(503200), &FWUpgradeSink::SendPacketN1, this, socket);
                }
                else if(seqNum == 2){
                    //reply with a packet of 41 bytes in size
                    header.SetSeq((uint32_t)3);
                    pack = Create<Packet>(41 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #3 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #2 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 4){
                    //reply with a packet of 147 bytes in size
                    header.SetSeq((uint32_t)5);
                    pack = Create<Packet>(147 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #5 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #4 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 6){
                    //reply with a packet of 19 bytes in size
                    header.SetSeq((uint32_t)7);
                    pack = Create<Packet>(19 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #7 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #6 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 8){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)9);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #9 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #8 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 10){
                    //reply with a packet of 29 bytes in size
                    header.SetSeq((uint32_t)11);
                    pack = Create<Packet>(29 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #11 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #10 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 12){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)13);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #13 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #12 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    //establish a TCP connection
                    if (!m_remoteTCPSocket){
                        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                        m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);
                        
                        Ipv4Address targetAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
                        uint16_t portN = 33078;
                        
                        if (Ipv4Address::IsMatchingType(targetAddress) == true)
                            m_remoteTCPSocket->Bind ();

                        m_remoteTCPSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(targetAddress), portN));
                        m_remoteTCPSocket->SetAllowBroadcast (true);
                        m_remoteTCPSocket->ShutdownRecv ();

                        m_remoteTCPSocket->SetConnectCallback (
                                    MakeCallback (&FWUpgradeSink::ConnectionSucceeded, this),
                                    MakeCallback (&FWUpgradeSink::ConnectionFailed, this));
                    }
                    
//                    NS_LOG_INFO("Time: " << Simulator::Now().GetNanoSeconds());
//                               
////                    uint32_t microseconds;
////                    microseconds = (uint32_t)1000000;
////                    usleep(microseconds);
//                    
//                    NS_LOG_INFO("Time: " << Simulator::Now().GetNanoSeconds());
//                    
//                    Simulator::Schedule(NanoSeconds(400000000), &FWUpgradeSink::SetDelayFlag, this);
//                    for(;;){
//                        if(m_bDelayFlag == false)
//                            break;
//                        NS_LOG_INFO("While Loop!!!");
//                    }
//                    m_bDelayFlag = true;
                    //send a packet of 95 bytes in size
                    Simulator::Schedule(NanoSeconds(14954545000), &FWUpgradeSink::SendPacketN14, this, socket);
//                    SeqTsHeader header2;
//                    header2.SetSeq((uint32_t)14);
//                    Ptr<Packet> pack2 = Create<Packet>(95 - header2.GetSerializedSize());
//                    pack2->AddHeader(header2);
//                    m_txTrace(pack2);
//                    socket->Send(pack2);
//                    
//                    NS_LOG_DEBUG ("The GATEWAY has sent the #14 FTP packet in size of " << 
//                                    pack2->GetSize() << " in the end of downloading the file at " << 
//                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 15){
                    //reply with a packet of 67 bytes in size
                    header.SetSeq((uint32_t)16);
                    pack = Create<Packet>(67 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #16 in size of " << 
                                    pack->GetSize() << " in response to the FTP packet #15 at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    m_completionTS = Simulator::Now();
                }
                else NS_LOG_ERROR("We have a problem with the message type!!!");
            }
        }
    }
    
    void FWUpgradeSink::HandleACKandFTP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom (from))) {
            if (packet->GetSize () == 0) //EOF
                break;
            
            Time now = Simulator::Now();
            
            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
            IPEventIdMap::iterator iterator;
            iterator = m_IpEventIdMap.find(hostOrderIpAddress);

            if(iterator != m_IpEventIdMap.end()){
                EventId eventId = iterator->second;
                Simulator::Cancel (eventId);
                NS_LOG_INFO("Event " << eventId.GetUid() << " was canceled!!!");
                m_nRecACKs++;
                NS_LOG_INFO("The # of ACKs: " << m_nRecACKs);
            }
            else NS_LOG_INFO("We have a problem with Ip-Event map!!!");

            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();

            m_rxCount += 1.0;

            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("The GATEWAY has received an FTP packet in size of " << 
                    m_rxBytes << " from " << 
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now().GetSeconds() << " s");
                
                Ptr<Packet> pack;
                SeqTsHeader header;
                if(seqNum == 2){
                    //reply with a packet of 41 bytes in size
                    header.SetSeq((uint32_t)3);
                    pack = Create<Packet>(41 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #3 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #2 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 4){
                    //reply with a packet of 147 bytes in size
                    header.SetSeq((uint32_t)5);
                    pack = Create<Packet>(147 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #5 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #4 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 6){
                    //reply with a packet of 19 bytes in size
                    header.SetSeq((uint32_t)7);
                    pack = Create<Packet>(19 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #7 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #6 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 8){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)9);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #9 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #8 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 10){
                    //reply with a packet of 29 bytes in size
                    header.SetSeq((uint32_t)11);
                    pack = Create<Packet>(29 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #11 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #10 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 12){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)13);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #13 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #12 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    //establish a TCP connection
                    if (!m_remoteTCPSocket){
                        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                        m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);
                        
                        Ipv4Address targetAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
                        uint16_t portN = 33078;
                        
                        if (Ipv4Address::IsMatchingType(targetAddress) == true)
                            m_remoteTCPSocket->Bind ();

                        m_remoteTCPSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(targetAddress), portN));
                        m_remoteTCPSocket->SetAllowBroadcast (true);
                        m_remoteTCPSocket->ShutdownRecv ();

                        m_remoteTCPSocket->SetConnectCallback (
                                    MakeCallback (&FWUpgradeSink::ConnectionSucceeded, this),
                                    MakeCallback (&FWUpgradeSink::ConnectionFailed, this));
                    }
                    
//                    NS_LOG_INFO("Time: " << Simulator::Now().GetNanoSeconds());
//                               
////                    uint32_t microseconds;
////                    microseconds = (uint32_t)1000000;
////                    usleep(microseconds);
//                    
//                    NS_LOG_INFO("Time: " << Simulator::Now().GetNanoSeconds());
//                    
//                    Simulator::Schedule(NanoSeconds(400000000), &FWUpgradeSink::SetDelayFlag, this);
//                    for(;;){
//                        if(m_bDelayFlag == false)
//                            break;
//                        NS_LOG_INFO("While Loop!!!");
//                    }
//                    m_bDelayFlag = true;
                    //send a packet of 95 bytes in size
//                    Simulator::Schedule(NanoSeconds(400000000), &FWUpgradeSink::SendPacketN14, this, socket);
                    Simulator::Schedule(NanoSeconds(14954545000), &FWUpgradeSink::SendPacketN14, this, socket);
//                    SeqTsHeader header2;
//                    header2.SetSeq((uint32_t)14);
//                    Ptr<Packet> pack2 = Create<Packet>(95 - header2.GetSerializedSize());
//                    pack2->AddHeader(header2);
//                    m_txTrace(pack2);
//                    socket->Send(pack2);
//                    
//                    NS_LOG_DEBUG ("The GATEWAY has sent the #14 FTP packet in size of " << 
//                                    pack2->GetSize() << " in the end of downloading the file at " << 
//                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 15){
                    //reply with a packet of 67 bytes in size
                    header.SetSeq((uint32_t)16);
                    pack = Create<Packet>(67 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #16 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #15 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    m_completionTS = Simulator::Now();
                }
                else NS_LOG_ERROR("We have a problem with the message type!!!");
            }
        }
    }
    
    void FWUpgradeSink::SendPacketN1(Ptr<Socket> socket){
        SeqTsHeader header;
        Ptr<Packet> pack;
        header.SetSeq((uint32_t)1);
        pack = Create<Packet>(237-header.GetSerializedSize());
        pack->AddHeader(header);

        m_txTrace(pack);
        socket->Send(pack);

        NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #1 in size of " << 
                        pack->GetSize() << " in response to the FTP packet #0 at " << 
                        Simulator::Now().GetSeconds() << " s");
    }
    
    void FWUpgradeSink::SendPacketN14(Ptr<Socket> socket){
        SeqTsHeader header2;
        header2.SetSeq((uint32_t)14);
        Ptr<Packet> pack2 = Create<Packet>(95 - header2.GetSerializedSize());
        pack2->AddHeader(header2);
        m_txTrace(pack2);
        socket->Send(pack2);

        NS_LOG_DEBUG ("The GATEWAY has sent the FTP packet #14 in size of " << 
                        pack2->GetSize() << " in the end of downloading the file at " << 
                        Simulator::Now().GetSeconds() << " s");
    }
    
    void FWUpgradeSink::HandleReadTCPConn2 (Ptr<Socket> socket){
        
    }

    void FWUpgradeSink::HandleReport(Ptr<Packet> packet, Address from, Ptr<Socket> socket){
        uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
        m_SocketAddressMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
        
        MeterSeqNumMap::iterator itSeq;
        itSeq = m_SocketAddressMap.find(hostOrderIpAddress);
        
        uint32_t m_rxBytes = packet->GetSize();
        SeqTsHeader header;
        packet->RemoveHeader(header);
        uint32_t seqNum = header.GetSeq ();
        Time txtime = header.GetTs ();
        
        m_rxCount += 1.0;
        
        StatRecord tmp;
        tmp.round = seqNum;
        tmp.rxCount = 1;
        tmp.rxBytes = m_rxBytes;
        tmp.totDelay = (itSeq->second.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
        tmp.firstRxTime = itSeq->second;
        tmp.lastRxTime = itSeq->second;
        tmp.minTxTime = txtime;
        m_stat.push_back(tmp);
        
        if (InetSocketAddress::IsMatchingType (from)){
            if(m_mode == 0 || m_mode == 2){
                NS_LOG_DEBUG ("The GATEWAY has received a signcrypted challenge in size of " << 
                    m_rxBytes << " from " << 
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    itSeq->second.GetSeconds() << " s");
                
                uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
                
                IPTSMap::iterator IpTsMAP;
                IpTsMAP = m_IpTimeStampMap.find(hostOrderIpAddress);

                if(IpTsMAP == m_IpTimeStampMap.end()){
                    m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                    m_nRecACKs++;
                }
                
                if(m_nRecACKs == (m_nSMs-1)){
                    Simulator::Cancel (m_alarmEvent);
                    Simulator::Cancel (m_reTXEvent);
                }
            }
            else if(m_mode == 1){
                NS_LOG_DEBUG ("The GATEWAY has received an encrypted challenge in size of " << 
                    m_rxBytes << " from " << 
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now().GetSeconds() << " s");
            }
            else if(m_mode == 4){
                NS_LOG_DEBUG ("The GATEWAY has received an FTP packet in size of " << 
                    m_rxBytes << " from " << 
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now().GetSeconds() << " s");
                
                Ptr<Packet> pack;
                SeqTsHeader header;
                if(seqNum == 2){
                    //reply with a packet of 41 bytes in size
                    header.SetSeq((uint32_t)3);
                    pack = Create<Packet>(41 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #3 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #2 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 4){
                    //reply with a packet of 147 bytes in size
                    header.SetSeq((uint32_t)5);
                    pack = Create<Packet>(147 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #5 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #4 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 6){
                    //reply with a packet of 19 bytes in size
                    header.SetSeq((uint32_t)7);
                    pack = Create<Packet>(19 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #7 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #6 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 8){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)9);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #9 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #8 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 10){
                    //reply with a packet of 29 bytes in size
                    header.SetSeq((uint32_t)11);
                    pack = Create<Packet>(29 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #11 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #10 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 12){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)13);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #13 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #12 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    //establish a TCP connection
                    if (!m_remoteTCPSocket){
                        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                        m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);
                        
                        Ipv4Address targetAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
                        uint16_t portN = 33078;
                        
                        if (Ipv4Address::IsMatchingType(targetAddress) == true)
                            m_remoteTCPSocket->Bind ();

                        m_remoteTCPSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(targetAddress), portN));
                        m_remoteTCPSocket->SetAllowBroadcast (true);
                        m_remoteTCPSocket->ShutdownRecv ();

                        m_remoteTCPSocket->SetConnectCallback (
                                    MakeCallback (&FWUpgradeSink::ConnectionSucceeded, this),
                                    MakeCallback (&FWUpgradeSink::ConnectionFailed, this));
                    }
                    
                    Simulator::Schedule(NanoSeconds(400000000), &FWUpgradeSink::SetDelayFlag, this);
                    while(m_bDelayFlag){}
                    m_bDelayFlag = true;
                    //send a packet of 95 bytes in size
                    SeqTsHeader header2;
                    header2.SetSeq((uint32_t)14);
                    Ptr<Packet> pack2 = Create<Packet>(95 - header2.GetSerializedSize());
                    pack2->AddHeader(header2);
                    m_txTrace(pack2);
                    m_localTCPsocket->Send(pack2);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #14 FTP packet in size of " << 
                                    pack2->GetSize() << " in the end of downloading the file at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 15){
                    //reply with a packet of 67 bytes in size
                    header.SetSeq((uint32_t)16);
                    pack = Create<Packet>(67 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    m_localTCPsocket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #16 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #15 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    m_completionTS = Simulator::Now();
                }
                else NS_LOG_ERROR("We have a problem with the message type!!!");
            }
        }
    }
    
    void FWUpgradeSink::HandleFTPMode8 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom (from))) {
            if (packet->GetSize () == 0) //EOF
                break;
            
            Time now = Simulator::Now();
            
            uint32_t hostOrderIpAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ().Get();
            IPTSMap::iterator IpTsMAP;
            IpTsMAP = m_IpTimeStampMap.find(hostOrderIpAddress);
            if(IpTsMAP == m_IpTimeStampMap.end()){
                m_IpTimeStampMap.insert(std::make_pair(hostOrderIpAddress, Simulator::Now()));
                m_nRecACKs++;
            }
            if(m_nRecACKs == (m_nSMs-1)){
                Simulator::Cancel (m_sendEvent);
                NS_LOG_INFO("The GATEWAY has received all ACKs!!!");
            }

            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();

            m_rxCount += 1.0;
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("The GATEWAY has received an FTP packet in size of " << 
                                m_rxBytes << " from " << 
                                InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" <<
                                InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                                Simulator::Now().GetSeconds() << " s");
                
                Ptr<Packet> pack;
                SeqTsHeader header;
                if(seqNum == 2){
                    //reply with a packet of 41 bytes in size
                    header.SetSeq((uint32_t)3);
                    pack = Create<Packet>(41 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #3 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #2 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 4){
                    //reply with a packet of 147 bytes in size
                    header.SetSeq((uint32_t)5);
                    pack = Create<Packet>(147 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #5 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #4 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 6){
                    //reply with a packet of 19 bytes in size
                    header.SetSeq((uint32_t)7);
                    pack = Create<Packet>(19 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #7 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #6 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 8){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)9);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #9 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #8 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 10){
                    //reply with a packet of 29 bytes in size
                    header.SetSeq((uint32_t)11);
                    pack = Create<Packet>(29 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #11 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #10 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                }
                else if(seqNum == 12){
                    //reply with a packet of 30 bytes in size
                    header.SetSeq((uint32_t)13);
                    pack = Create<Packet>(30 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #13 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #12 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    //establish a TCP connection
                    if (!m_remoteTCPSocket){
                        TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                        m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);
                        
                        Ipv4Address targetAddress = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
                        uint16_t portN = 33078;
                        
                        if (Ipv4Address::IsMatchingType(targetAddress) == true)
                            m_remoteTCPSocket->Bind ();

                        m_remoteTCPSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(targetAddress), portN));
                        m_remoteTCPSocket->SetAllowBroadcast (true);
                        m_remoteTCPSocket->ShutdownRecv ();

                        m_remoteTCPSocket->SetConnectCallback (
                                    MakeCallback (&FWUpgradeSink::ConnectionSucceeded, this),
                                    MakeCallback (&FWUpgradeSink::ConnectionFailed, this));
                    }

                    //send a packet of 95 bytes in size
                    Simulator::Schedule(NanoSeconds(14954545000), &FWUpgradeSink::SendPacketN14, this, socket);
                }
                else if(seqNum == 15){
                    //reply with a packet of 67 bytes in size
                    header.SetSeq((uint32_t)16);
                    pack = Create<Packet>(67 - header.GetSerializedSize());
                    pack->AddHeader(header);
                    m_txTrace(pack);
                    socket->Send(pack);
                    
                    NS_LOG_DEBUG ("The GATEWAY has sent the #16 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #15 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
                    
                    m_completionTS = Simulator::Now();
                }
                else NS_LOG_ERROR("We have a problem with the message type!!!");
            }
        }
    }
    
    void FWUpgradeSink::SetDelayFlag(void){
        m_bDelayFlag = false;
    }

    void FWUpgradeSink::ConnectionSucceeded (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        NS_LOG_DEBUG("Node " << GetNode()->GetId() << 
                    " successfully established a TCP connection at " << Simulator::Now().GetSeconds() << " s!!!");
        m_connected = true;
    }

    void FWUpgradeSink::ConnectionFailed (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        NS_LOG_DEBUG("Connection Failed");
    }

    bool FWUpgradeSink::IsThereAnyPreviousStoredPacket(Address from){
        bool lfoundPacket = false;
        for(std::vector<DataWaitingPacket>::iterator it = m_waitingPacket.begin(); it != m_waitingPacket.end(); ++it) {
           if(it->from == from) {
              lfoundPacket=true;
              break;
           }
        }     
        return lfoundPacket;
    }

    void FWUpgradeSink::StatPrint (){
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

    void FWUpgradeSink::ReportStat (std::ostream & os){
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

    void FWUpgradeSink::HandleAcceptMode4 (Ptr<Socket> s, const Address& from){
        NS_LOG_FUNCTION (this << s << from);
        s->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadMode4, this));
        m_socketList.push_back (s);
    }
    
    void FWUpgradeSink::HandleAcceptTCPConn2 (Ptr<Socket> s, const Address& from){
        NS_LOG_FUNCTION (this << s << from);
        s->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleReadTCPConn2, this));
        m_socketList.push_back (s);
        
//        if (InetSocketAddress::IsMatchingType (from)){
//            NS_LOG_DEBUG ("The GTW accepted a TCP connection from " <<
//                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" << 
//                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
//                    Simulator::Now ().GetSeconds () << " s");
//        }
//        
//        SeqTsHeader header;
//        header.SetSeq((uint32_t)1);
//        Ptr<Packet> packet= Create<Packet>(237-header.GetSerializedSize());
//        packet->AddHeader(header);
//        
//        m_txTrace(packet);
////        m_localTCPsocket->Send(packet);
//        s->Send(packet);
//        
//        NS_LOG_INFO ("The GTW initiated the FTP protocol by sending a packet of " << 
//                packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
    }
    
    void FWUpgradeSink::HandleAcceptACKandFTP (Ptr<Socket> s, const Address& from){
        NS_LOG_FUNCTION (this << s << from);
        s->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleACKandFTP, this));
        m_socketList.push_back (s);
        
        if (InetSocketAddress::IsMatchingType (from)){
            NS_LOG_DEBUG ("The GTW accepted a TCP connection from " <<
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" << 
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now ().GetSeconds () << " s");
        }
        
        SeqTsHeader header;
        header.SetSeq((uint32_t)1);
        Ptr<Packet> packet= Create<Packet>(237-header.GetSerializedSize());
        packet->AddHeader(header);
        
        m_txTrace(packet);
//        m_localTCPsocket->Send(packet);
        s->Send(packet);
        
        NS_LOG_INFO ("The GTW initiated the FTP protocol by sending a packet of " << 
                packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
    }
    
    void FWUpgradeSink::HandleAcceptTCPMode8 (Ptr<Socket> s, const Address& from){
        NS_LOG_FUNCTION (this << s << from);
        s->SetRecvCallback (MakeCallback (&FWUpgradeSink::HandleFTPMode8, this));
        m_socketList.push_back (s);
        
        if (InetSocketAddress::IsMatchingType (from)){
            NS_LOG_DEBUG ("The GTW accepted a TCP connection from " <<
                    InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" << 
                    InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                    Simulator::Now ().GetSeconds () << " s");
        }
        
        SeqTsHeader header;
        header.SetSeq((uint32_t)1);
        Ptr<Packet> packet= Create<Packet>(237-header.GetSerializedSize());
        packet->AddHeader(header);
        
        m_txTrace(packet);
//        m_localTCPsocket->Send(packet);
        s->Send(packet);
        
        NS_LOG_INFO ("The GTW initiated the FTP protocol by sending a packet of " << 
                packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
    }
    
    void FWUpgradeSink::HandlePeerClose (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
    }
    void FWUpgradeSink::HandlePeerError (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
    }
} // Namespace ns3