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
 */
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/boolean.h"

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
#include "fw-upgrade-source.h"
#include "seq-ts-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/net-device-container.h"

#include <ns3/double.h>

static uint32_t m_nReceipts = 0;
//static bool written = false;

namespace ns3 {
    NS_LOG_COMPONENT_DEFINE ("FWUpgradeSourceNW");

    NS_OBJECT_ENSURE_REGISTERED (FWUpgradeSource);

    TypeId FWUpgradeSource::GetTypeId (void){
        static TypeId tid = TypeId ("ns3::FWUpgradeSourceNW")
            .SetParent<Application> ()
            .SetGroupName("Applications")
            .AddConstructor<FWUpgradeSource> ()
            .AddAttribute ("MaxPackets", 
                           "The maximum number of packets the application will send",
                           UintegerValue (100),
                           MakeUintegerAccessor (&FWUpgradeSource::m_count),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("NChildSMs", 
                           "The maximum number of packets the application will send",
                           UintegerValue (8),
                           MakeUintegerAccessor (&FWUpgradeSource::m_nChildSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("NSMs", 
                           "The number of smart meters in the network",
                           UintegerValue (36),
                           MakeUintegerAccessor (&FWUpgradeSource::m_nSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Targeted", "Check if the firmware upgrade targets this SM",
                            BooleanValue (false),
                            MakeBooleanAccessor (&FWUpgradeSource::m_boolTargeted),
                            MakeBooleanChecker ())
            .AddAttribute ("NTargetedSMs", 
                           "The maximum number of packets the application will send",
                           UintegerValue (10),
                           MakeUintegerAccessor (&FWUpgradeSource::m_nTargetedSMs),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Mode", "The default size of packets received",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSource::m_mode),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("Interval", 
                           "The time to wait between packets",
                           TimeValue (Seconds (1.0)),
                           MakeTimeAccessor (&FWUpgradeSource::m_interval),
                           MakeTimeChecker ())
            .AddAttribute ("ConnectionReqPeriod",
                           "Connection Request Period",
                           TimeValue (Seconds (2.0)),
                           MakeTimeAccessor (&FWUpgradeSource::m_connReqPeriod),
                           MakeTimeChecker ())
            .AddAttribute ("RemoteAddress", 
                           "The destination Address of the outbound packets",
                           AddressValue (),
                           MakeAddressAccessor (&FWUpgradeSource::m_peerAddress),
                           MakeAddressChecker ())
            .AddAttribute ("RemotePort", 
                           "The destination port of the outbound packets",
                           UintegerValue (0),
                           MakeUintegerAccessor (&FWUpgradeSource::m_peerPort),
                           MakeUintegerChecker<uint16_t> ())
            .AddAttribute ("Delay", "The default size of packets received",
                           UintegerValue (55837000),
                           MakeUintegerAccessor (&FWUpgradeSource::m_procDelay),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("PacketSize", "Size of echo data in outbound packets",
                           UintegerValue (100),
                           MakeUintegerAccessor (&FWUpgradeSource::SetDataSize,
                                                 &FWUpgradeSource::GetDataSize),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("SigncryptedChallengeSize", "The default size of SC(H_Up) received",
                           UintegerValue (1013),
                           MakeUintegerAccessor (&FWUpgradeSource::m_SCH_UpSize),
                           MakeUintegerChecker<uint32_t> ())
            .AddAttribute ("ActiveTimePeriod",
                           "The time period in which the gateway and other SMs can communicate data",
                           DoubleValue (400.0),
                           MakeDoubleAccessor (&FWUpgradeSource::m_activeTP),
                           MakeDoubleChecker<double> ())
            .AddAttribute ("FirstSending",
                           "The time period in which the gateway and other SMs can communicate data",
                           TimeValue (Seconds(100.0)),
                           MakeTimeAccessor (&FWUpgradeSource::m_firstSendTime),
                           MakeTimeChecker())
            .AddTraceSource ("Tx", "A new packet is created and is sent",
                             MakeTraceSourceAccessor (&FWUpgradeSource::m_txTrace),
                             "ns3::Packet::TracedCallback");
        return tid;
    }

    FWUpgradeSource::FWUpgradeSource (){
        NS_LOG_FUNCTION (this);
        m_sent = 0;
        m_socket = 0;
        m_sendEvent = EventId ();
        m_ACKEvent = EventId ();
        m_data = 0;
        m_dataSize = 0;
        m_tSent = 0;
        m_tReceived = 0;
        m_connected = false;
        m_challengeSent = false;
        m_bFWUReqReceived = false;
        m_bFWUFReceived = false;
        m_rxCount = 0.0;
        m_mode = 0;
    }
    
    FWUpgradeSource::FWUpgradeSource(kodocpp::codec codeType,
                                    kodocpp::field field,
                                    uint32_t generationSize,
                                    uint32_t packetSize)
                                   : m_codeType (codeType),
                                     m_field (field),
                                     m_generationSize (generationSize),
                                     m_packetSize (packetSize){
        NS_LOG_FUNCTION (this);
        m_sent = 0;
        m_socket = 0;
        m_sendEvent = EventId ();
        m_ACKEvent = EventId ();
        m_data = 0;
        m_dataSize = 0;
        m_tSent = 0;
        m_tReceived = 0;
        m_connected = false;
        m_challengeSent = false;
        m_bFWUReqReceived = false;
        m_bFWUFReceived = false;
        m_rxCount = 0.0;
        m_mode = 0;
        
        srand(static_cast<uint32_t>(time(0)));
        
        // Create the encoder factory using the supplied parameters
        kodocpp::decoder_factory decoderFactory (m_codeType, m_field, m_generationSize, m_packetSize);
        
        // Create encoder and disable systematic mode
        m_decoder = decoderFactory.build ();
        
//        // Add custom trace callback to each decoder
//        auto callback = [](const std::string& zone, const std::string& data){
//            std::set<std::string> filters = { "decoder_state", "symbol_coefficients_before_read_symbol" };
//            if (filters.count (zone)){
//                std::cout << zone << ":" << std::endl;
//                std::cout << data << std::endl;
//            }
//        };
//        
//        m_decoder.set_trace_callback (callback);
        m_decoderBuffer.resize (m_decoder.block_size ());
        m_decoder.set_mutable_symbols (m_decoderBuffer.data (), m_decoder.block_size ());
    }
    
    FWUpgradeSource::FWUpgradeSource(kodocpp::codec codeType,
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
        m_sent = 0;
        m_socket = 0;
        m_sendEvent = EventId ();
        m_ACKEvent = EventId ();
        m_data = 0;
        m_dataSize = 0;
        m_tSent = 0;
        m_tReceived = 0;
        m_connected = false;
        m_challengeSent = false;
        m_bFWUReqReceived = false;
        m_bFWUFReceived = false;
        m_rxCount = 0.0;
        m_mode = 0;
        
        srand(static_cast<uint32_t>(time(0)));
        
        // Create the encoder factory using the supplied parameters
        kodocpp::decoder_factory decoderFactory (m_codeType, m_field, m_generationSize, m_packetSize);
        
        m_decoders.resize(m_nBatches);
        m_decoderBuffers.resize(m_nBatches);
        
        // Add custom trace callback to each decoder
//        auto callback = [](const std::string& zone, const std::string& data){
//            std::set<std::string> filters = { "decoder_state", "symbol_coefficients_before_read_symbol" };
//            if (filters.count (zone)){
//                std::cout << zone << ":" << std::endl;
//                std::cout << data << std::endl;
//            }
//        };
        
        for(int i=0; i<(int)m_nBatches; i++){
            // Create decoder and disable systematic mode
            m_decoders[i] = decoderFactory.build ();
            
//            m_decoders[i].set_trace_callback (callback);
            m_decoderBuffers[i].resize (m_decoders[i].block_size ());
            m_decoders[i].set_mutable_symbols (m_decoderBuffers[i].data (), m_decoders[i].block_size ());
        }
    }

    FWUpgradeSource::~FWUpgradeSource(){
        NS_LOG_FUNCTION (this);
        m_socket = 0;

        delete [] m_data;
        m_data = 0;
        m_dataSize = 0;
        
        if(m_mode == 4)
            PrintStatsMode4();
        else if(m_mode == 6)
            PrintStatsMode6();
        else if(m_mode == 8)
            PrintStatsMode8();
        else
            PrintStats();
    }

    void FWUpgradeSource::SetRemote (Address ip, uint16_t port){
        NS_LOG_FUNCTION (this << ip << port);
        m_peerAddress = ip;
        m_peerPort = port;
    }

    void FWUpgradeSource::SetRemote (Ipv4Address ip, uint16_t port){
        NS_LOG_FUNCTION (this << ip << port);
        m_peerAddress = Address (ip);
        m_peerPort = port;
    }

    void FWUpgradeSource::SetRemote (Ipv6Address ip, uint16_t port){
        NS_LOG_FUNCTION (this << ip << port);
        m_peerAddress = Address (ip);
        m_peerPort = port;
    }

    void FWUpgradeSource::DoDispose (void){
        NS_LOG_FUNCTION (this);
        Application::DoDispose ();
    }
    
    void FWUpgradeSource::SetTargetedSMAddress (Address address){
        NS_LOG_FUNCTION (this << address);
        
        m_targetedSMAddressList.push_back(address);
    }
    Address FWUpgradeSource::GetTargetedSMAddress (uint32_t index){
        NS_LOG_FUNCTION (this << index);
        
        return m_targetedSMAddressList[index];
    }
    
    void FWUpgradeSource::StartApplication (void){
        NS_LOG_FUNCTION (this);

        if(m_mode == 0 || m_mode == 1){
            NS_LOG_INFO("Mode: " << m_mode);
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleRead, this));
            m_socket->SetAllowBroadcast (true);
        }
        else if(m_mode == 2){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }

            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleRead, this));
            m_socket->SetAllowBroadcast (true);
            
            m_targetedSMSockets = (Ptr<Socket> *)calloc(m_nChildSMs, sizeof(Ptr<Socket>));
            
//            for(int i=0; i<(int)m_nChildSMs; i++){
//                m_targetedSMSockets[i] = NULL;
//            }
            
//            NS_LOG_INFO("# of Child SMs: " << m_nChildSMs);
            
            for(int i=0; i<(int)m_nChildSMs; i++){
                if(!m_targetedSMSockets[i]){
//                    NS_LOG_INFO("Girdi!!!");
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
        }
        else if(m_mode == 3){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode3, this));
            m_socket->SetAllowBroadcast (true);
            
            copySocket = Socket::CreateSocket (GetNode (), tid);

            Address broadcastAddress = Ipv4Address ("10.1.1.255");
            uint16_t broadcastPort = 2048;

            if (Ipv4Address::IsMatchingType(broadcastAddress) == true){
                copySocket->Bind ();
                copySocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(broadcastAddress), broadcastPort));
            }
            
            copySocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            copySocket->SetAllowBroadcast (true);
        }
        else if(m_mode == 4){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode4, this));
            m_socket->SetAllowBroadcast (true);
            
            copySocket = Socket::CreateSocket (GetNode (), tid);
            Address broadcastAddress = Ipv4Address ("10.1.1.255");
            uint16_t broadcastPort = 2048;
            if (Ipv4Address::IsMatchingType(broadcastAddress) == true){
                copySocket->Bind ();
                copySocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(broadcastAddress), broadcastPort));
            }
            copySocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            copySocket->SetAllowBroadcast (true);
            
            if(!m_localTCPsocket){  // A socket for listening the challenge sent by the SMs
                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress localAddress = InetSocketAddress (Ipv4Address::GetAny (), 33078);

                m_localTCPsocket->Bind (localAddress);
                m_localTCPsocket->Listen ();
                m_localTCPsocket->SetAcceptCallback (
                    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                    MakeCallback (&FWUpgradeSource::HandleAccept, this));
                m_localTCPsocket->SetCloseCallbacks (
                    MakeCallback (&FWUpgradeSource::HandlePeerClose, this),
                    MakeCallback (&FWUpgradeSource::HandlePeerError, this));

                m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadFTP, this));
            }
        }
        else if(m_mode == 5){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode5, this));
            m_socket->SetAllowBroadcast (true);
        }
        else if(m_mode == 6){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode6, this));
            m_socket->SetAllowBroadcast (true);
        }
        else if(m_mode == 7){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode7, this));
            m_socket->SetAllowBroadcast (true);
        }
        else if(m_mode == 8){
            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
            if(!m_ACKSocket){
                m_ACKSocket = Socket::CreateSocket (GetNode (), tid);
                
                Address ackAddress = InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 ();
                uint16_t portNumber = 1024;
                
                if (Ipv4Address::IsMatchingType(ackAddress) == true){
                    m_ACKSocket->Bind ();
                    m_ACKSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(ackAddress), portNumber));
                }
                else{
                    NS_ASSERT_MSG (false, "Incompatible address type: " << m_peerAddress);
                }
            }
            m_ACKSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_ACKSocket->SetAllowBroadcast (true);
            
            if (!m_socket){
                m_socket = Socket::CreateSocket (GetNode (), tid);
                InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 2048);
                m_socket->Bind (local);

                if (addressUtils::IsMulticast (m_local)){
                    Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
                    if (udpSocket){
                        // equivalent to setsockopt (MCAST_JOIN_GROUP)
                        udpSocket->MulticastJoinGroup (0, m_local);
                    }
                    else
                        NS_FATAL_ERROR ("Error: Failed to join multicast group");
                }
            }
            m_socket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadMode8, this));
            m_socket->SetAllowBroadcast (true);
            
            if(!m_localTCPsocket){  // A socket for listening the challenge sent by the SMs
                TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
                m_localTCPsocket = Socket::CreateSocket (GetNode (), tid);
                
                InetSocketAddress localAddress = InetSocketAddress (Ipv4Address::GetAny (), 33078);

                m_localTCPsocket->Bind (localAddress);
                m_localTCPsocket->Listen ();
                m_localTCPsocket->SetAcceptCallback (
                    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
                    MakeCallback (&FWUpgradeSource::HandleAccept, this));
                m_localTCPsocket->SetCloseCallbacks (
                    MakeCallback (&FWUpgradeSource::HandlePeerClose, this),
                    MakeCallback (&FWUpgradeSource::HandlePeerError, this));

                m_localTCPsocket->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadFTP, this));
            }
        }
        else NS_LOG_ERROR("We have a problem with the mode: " << (int)(m_mode));
        
//        if (!m_remoteUDPSocket){
//            TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
//            m_remoteUDPSocket = Socket::CreateSocket (GetNode (), tid);
//            
//            Address peerAddress = Ipv4Address ("10.1.1.255");
//            uint16_t peerPort = 2048;
//            
//            if (Ipv4Address::IsMatchingType(peerAddress) == true){
//                m_remoteUDPSocket->Bind ();
//                m_remoteUDPSocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(peerAddress), peerPort));
//            }
//            else if (Ipv6Address::IsMatchingType(peerAddress) == true){
//                m_remoteUDPSocket->Bind6 ();
//                m_remoteUDPSocket->Connect (Inet6SocketAddress (Ipv6Address::ConvertFrom(peerAddress), peerPort));
//            }
//            else if (InetSocketAddress::IsMatchingType (peerAddress) == true){
//                m_remoteUDPSocket->Bind ();
//                m_remoteUDPSocket->Connect (peerAddress);
//            }
//            else if (Inet6SocketAddress::IsMatchingType (peerAddress) == true){
//                m_remoteUDPSocket->Bind6 ();
//                m_remoteUDPSocket->Connect (peerAddress);
//            }
//            else{
//                NS_ASSERT_MSG (false, "Incompatible address type: " << peerAddress);
//            }
//        }
        m_nodeId = GetNode()->GetId();
    }
    
    void FWUpgradeSource::HandlePeerClose (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
    }

    void FWUpgradeSource::HandlePeerError (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
    }

    void FWUpgradeSource::HandleAccept (Ptr<Socket> s, const Address& from){
        NS_LOG_FUNCTION (this << s << from);
        s->SetRecvCallback (MakeCallback (&FWUpgradeSource::HandleReadFTP, this));
    }

    void FWUpgradeSource::ConnectionSucceededFTP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        NS_LOG_DEBUG("Node " << GetNode()->GetId() << 
              " successfully established a TCP connection at " << Simulator::Now().GetSeconds() << " s!!!");
        m_connected = true;
    }

    void FWUpgradeSource::ConnectionFailedFTP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        NS_LOG_INFO("Connection Failed");
    }

    void FWUpgradeSource::StopApplication (){
        NS_LOG_FUNCTION (this);

        if (m_socket != 0){
            m_socket->Close ();
            m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
            m_socket = 0;
        }

        Simulator::Cancel (m_sendEvent);
        Simulator::Cancel (m_ACKEvent);
    }
    
    void FWUpgradeSource::PrintStats(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
//            double delta;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << ": Total Delay = " << 
                        totDelay << " ms Total Bytes = " << totBytes << 
                        " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
//            delta = (lastRx.ToInteger (Time::US) - firstRx.ToInteger (Time::US))/1000000.0;
//            NS_LOG_INFO("Delta = " << delta);
//            throughput = ((totBytes*8)/1024)/delta;
            
            if(m_mode == 5 || m_mode == 6){
                totBytes += m_SCH_UpSize;
            }
            
            throughput = ((totBytes*8)/1024.0)/m_activeTP;
            NS_LOG_DEBUG("Total Bytes = " << totBytes << " Active Time Period = " << m_activeTP);
            
//            NS_LOG_INFO("XxX Source XxX: Node " << m_nodeId << ": Active Time Period = " << activeTimePeriod << " s");
            
            NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
                    " s Throughput = " << throughput << " kbps");
//            
//            if(!written){
//                if(m_mode == 0 || m_mode == 2 || m_mode == 4){
//                    NS_LOG_DEBUG("Receipts = " << m_nReceipts << " #SMs in the network = " << (m_nSMs-1));
//                    NS_LOG_INFO("SR = " << (((double)m_nReceipts)/(m_nSMs-1))*100 << " %");
//                }
//                else if(m_mode == 1 || m_mode == 5 || m_mode == 6){
//                    NS_LOG_DEBUG("Receipts = " << m_nReceipts << " #Targeted SMs in the network = " << m_nTargetedSMs);
//                    NS_LOG_INFO("SR = " << (((double)m_nReceipts)/m_nTargetedSMs)*100 << " %");
//                }
//                written = true;
//            }
        }
    }
    
    void FWUpgradeSource::PrintStatsMode4(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            double firstReceivedRequestDelay = 0;
            uint32_t totBytes = 0;
            uint32_t totTargetedBytes = 0;
            uint32_t totNoNTargetedBytes = 0;
            double avEtoEDelay = 0.0;
            Time firstReceiveTime = Simulator::Now();
//            double throughput = 0.0;    //Kbps
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;
                
                if(it->rxCount == 1000 && it->lastRxTime < firstReceiveTime)
                    firstReceiveTime = it->lastRxTime;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << ": Total Delay = " << 
                        totDelay << " ms Total Bytes = " << totBytes << 
                        " bytes.");
            }
            
            firstReceivedRequestDelay = (firstReceiveTime.ToInteger(Time::US) - m_firstSendTime.ToInteger(Time::US))/1000000.0;
            
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
            for(std::vector<StatRecord>::iterator it = m_statTargetedSMs.begin(); it != m_statTargetedSMs.end(); ++it) {
                totTargetedBytes += it->rxBytes;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << " Total Targeted Bytes = " << 
                        totTargetedBytes << " bytes.");
            }
            
            for(std::vector<StatRecord>::iterator it = m_statNoNTargetedSMs.begin(); it != m_statNoNTargetedSMs.end(); ++it) {
                totNoNTargetedBytes += it->rxBytes;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << " Total NoNTargeted Bytes = " << 
                        totNoNTargetedBytes << " bytes.");
            }
            
            double activeTimePeriod = m_activeTP; //(m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - m_stat[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            //double communicationThroughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            NS_LOG_INFO("XxX Source XxX: Node " << m_nodeId << ": Active Time Period = " << activeTimePeriod << " s");
            
//            if(m_bFWUFReceived)
//                totBytes += 2098692;    //FWUF
//            
//            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
//            double completionTime;
//            if(m_boolTargeted){
//                completionTime = (m_completionTS.ToInteger(Time::US) - 
//                                     m_stat[0].minTxTime.ToInteger(Time::US))/1000000.0;
//                NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
//                    " s Completion Time = " << completionTime << " s Throughput = " << throughput << " kbps");
//            }
//            else{
            
            if(m_bFWUFReceived)
                totTargetedBytes += 2098692;
            
            if(m_boolTargeted){
                double communicationTargetedThroughput = ((totTargetedBytes*8)/1024.0)/activeTimePeriod;
                NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
                            " s First Request Received Delay = " << firstReceivedRequestDelay << 
                            " s Targeted Throughput = " << communicationTargetedThroughput << " kbps");
            }
            else{
                double communicationNoNTargetedThroughput = ((totNoNTargetedBytes*8)/1024.0)/activeTimePeriod;
                NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
                            " s First Request Received Delay = " << firstReceivedRequestDelay << 
                            " s NoNTargeted Throughput = " << communicationNoNTargetedThroughput << " kbps");
            }
//            }
        }
    }
    
    void FWUpgradeSource::PrintStatsMode6(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << ": Total Delay = " << 
                        totDelay << " ms Total Bytes = " << totBytes << 
                        " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
//            totBytes += 2098692;    //FWUF
            double activeTimePeriod = m_activeTP;
            //(m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - m_stat[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
//            double communicationThroughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            NS_LOG_INFO("XxX Source XxX: Node " << m_nodeId << ": Active Time Period = " << activeTimePeriod << " s");
            
            if(m_bFWUFReceived)
                totBytes += 2098692;    //FWUF
            
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
//            double completionTime = (m_completionTS.ToInteger(Time::US) - 
//                                     m_stat[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
                        " s First Request Received Delay = " << m_stat[0].totDelay/1000000.0 << 
                        " s Targeted Throughput = " << throughput << " kbps");
        }
    }
    
    void FWUpgradeSource::PrintStatsMode8(){
        NS_LOG_FUNCTION(this);
        if(m_rxCount != 0.0){
            uint32_t totDelay = 0;
            uint32_t totBytes = 0;
            double avEtoEDelay = 0.0;
            double throughput = 0.0;    //Kbps
//            double delta;
            for(std::vector<StatRecord>::iterator it = m_stat.begin(); it != m_stat.end(); ++it) {
                totDelay += it->totDelay;
                totBytes += it->rxBytes;

                NS_LOG_DEBUG("XxX Source XxX: Node " << m_nodeId << ": Total Delay = " << 
                        totDelay << " ms Total Bytes = " << totBytes << 
                        " bytes.");
            }
            avEtoEDelay = totDelay/m_rxCount/1000000.0;
            
//            totBytes += 2098692;    //FWUF
            double activeTimePeriod = (m_stat[m_stat.size()-1].lastRxTime.ToInteger(Time::US) - 
                                      m_stat[0].minTxTime.ToInteger(Time::US))/1000000.0;
            
            double communicationThroughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            NS_LOG_INFO("XxX Source XxX: Node " << m_nodeId << ": Active Time Period = " << activeTimePeriod << " s");
            
            if(m_bFWUFReceived)
                totBytes += 2098692;    //FWUF
            
            throughput = ((totBytes*8)/1024.0)/activeTimePeriod;
            
            NS_LOG_INFO("CcC Source CcC: Node " << m_nodeId << ": Av. EtoE-Delay = " << avEtoEDelay << 
                    " s CommThroughput = " << communicationThroughput << " kbps Throughput = " << throughput << " kbps");
        }
    }

    void FWUpgradeSource::SetDataSize (uint32_t dataSize){
        NS_LOG_FUNCTION (this << dataSize);

        //
        // If the client is setting the echo packet data size this way, we infer
        // that she doesn't care about the contents of the packet at all, so 
        // neither will we.
        //
        delete [] m_data;
        m_data = 0;
        m_dataSize = 0;
        m_size = dataSize;
    }

    uint32_t FWUpgradeSource::GetDataSize (void) const{
        NS_LOG_FUNCTION (this);
        return m_size;
    }

    void FWUpgradeSource::SetFill (std::string fill){
        NS_LOG_FUNCTION (this << fill);

        uint32_t dataSize = fill.size () + 1;

        if (dataSize != m_dataSize){
            delete [] m_data;
            m_data = new uint8_t [dataSize];
            m_dataSize = dataSize;
        }

        memcpy (m_data, fill.c_str (), dataSize);

        //
        // Overwrite packet size attribute.
        //
        m_size = dataSize;
    }

    void FWUpgradeSource::SetFill (uint8_t fill, uint32_t dataSize){
        NS_LOG_FUNCTION (this << fill << dataSize);
        if (dataSize != m_dataSize){
            delete [] m_data;
            m_data = new uint8_t [dataSize];
            m_dataSize = dataSize;
        }

        memset (m_data, fill, dataSize);

        //
        // Overwrite packet size attribute.
        //
        m_size = dataSize;
    }

    void FWUpgradeSource::SetFill (uint8_t *fill, uint32_t fillSize, uint32_t dataSize){
        NS_LOG_FUNCTION (this << fill << fillSize << dataSize);
        if (dataSize != m_dataSize){
            delete [] m_data;
            m_data = new uint8_t [dataSize];
            m_dataSize = dataSize;
        }

        if (fillSize >= dataSize){
            memcpy (m_data, fill, dataSize);
            m_size = dataSize;
            return;
        }

        //
        // Do all but the final fill.
        //
        uint32_t filled = 0;
        while (filled + fillSize < dataSize){
            memcpy (&m_data[filled], fill, fillSize);
            filled += fillSize;
        }

        //
        // Last fill may be partial
        //
        memcpy (&m_data[filled], fill, dataSize - filled);

        //
        // Overwrite packet size attribute.
        //
        m_size = dataSize;
    }

    void FWUpgradeSource::ScheduleTransmit (Time dt){
        NS_LOG_FUNCTION (this << dt);
        m_sendEvent = Simulator::Schedule (dt, &FWUpgradeSource::Send, this);
    }

    void FWUpgradeSource::Send (void){
        NS_LOG_FUNCTION (this);

        NS_ASSERT (m_sendEvent.IsExpired ());

        Ptr<Packet> p;
        if (m_dataSize){
            //
            // If m_dataSize is non-zero, we have a data buffer of the same size that we
            // are expected to copy and send.  This state of affairs is created if one of
            // the Fill functions is called.  In this case, m_size must have been set
            // to agree with m_dataSize
            //
            NS_ASSERT_MSG (m_dataSize == m_size, "FWUpgradeSource::Send(): m_size and m_dataSize inconsistent");
            NS_ASSERT_MSG (m_data, "FWUpgradeSource::Send(): m_dataSize but no m_data");
            p = Create<Packet> (m_data, m_dataSize);
        }
        else{
            //
            // If m_dataSize is zero, the client has indicated that it doesn't care
            // about the data itself either by specifying the data size by setting
            // the corresponding attribute or by not calling a SetFill function.  In
            // this case, we don't worry about it either.  But we do allow m_size
            // to have a value different from the (zero) m_dataSize.
            //
            p = Create<Packet> (m_size);
        }
        
        // call to the trace sinks before the packet is actually sent,
        // so that tags added to the packet can be sent as well
        m_txTrace (p);
        m_socket->Send (p);

        if(m_sent == (uint32_t)0)
        m_tSent = Simulator::Now().GetNanoSeconds();

        ++m_sent;

        //  NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s EV (Node " << 
        //                   GetNode()->GetId() << ") sent " << m_size << " bytes to " <<
        //                   Ipv4Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);

        if (Ipv4Address::IsMatchingType (m_peerAddress)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s EV (Node " << 
            GetNode()->GetId() << ") sent " << m_size << " bytes to " <<
            Ipv4Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);
        }
        else if (Ipv6Address::IsMatchingType (m_peerAddress)){
            NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s EV (Node " << 
            GetNode()->GetId() << ") sent " << m_size << " bytes to " <<
            Ipv6Address::ConvertFrom (m_peerAddress) << " port " << m_peerPort);
        }

        if (m_sent < m_count)
            m_sendEvent = Simulator::Schedule (m_connReqPeriod, &FWUpgradeSource::Send, this);

        //  if (m_sent < m_count) 
        //    {
        //      ScheduleTransmit (m_interval);
        //    }
    }

    void FWUpgradeSource::HandleRead (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            m_rxCount += 1.0;
            
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            std::vector<uint8_t> payload (m_decoder.payload_size ());
            
            packet->CopyData (&payload[0], m_decoder.payload_size ());
            m_decoder.read_payload (&payload[0]);
            
            if(m_decoder.is_complete ()){
//                SeqTsHeader header2;
//                Ptr<Packet> packet2 = Create<Packet> (&m_decoderBuffer[0], m_decoderBuffer.size());
//                NS_LOG_INFO("Decoder Size: " << m_decoderBuffer.size());
//                packet2->RemoveHeader(header2);
//                uint32_t seqNum2 = header2.GetSeq ();
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received a Firmware Upgrade Request in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }
                
                m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACK, this);
                
                if(!m_challengeSent && m_boolTargeted){
                    Simulator::Schedule(NanoSeconds (m_procDelay), &FWUpgradeSource::SendH_Up, this);
                    m_challengeSent = true;
                }
            }
            
//            if(seqNum == 1000){
//                m_rxCount += 1.0;
//                m_nReceipts++;
//                if (InetSocketAddress::IsMatchingType (from)){
//                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received a Firmware Upgrade Request in size of " << 
//                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
//                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
//                            Simulator::Now ().GetSeconds () << " s");
//                }
//
//                m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACK, this);
//                
//                if(!m_challengeSent && m_boolTargeted){
//                    Simulator::Schedule(NanoSeconds (m_procDelay), &FWUpgradeSource::SendH_Up, this);
//                    m_challengeSent = true;
//                }
//                
//                m_copyPacket = packet->CreateFragment(0, packet->GetSize());
//                
//                m_bReqReceived = true;
//            }
//            else if(seqNum == 5000){
//                if (InetSocketAddress::IsMatchingType (from)){
//                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received an Alarm message in size of " << 
//                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
//                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
//                            Simulator::Now ().GetSeconds () << " s");
//                }
//                
//                if(m_bReqReceived){
//                    //There is a copy of the request
////                    if(!m_boolTargeted){
////                        //spread around the request
////                        
////                    }
//                    
//                    Ptr<Packet> copyPacket = m_copyPacket->CreateFragment(0, m_copyPacket->GetSize());
//                    SeqTsHeader copyHeader;
//                    copyHeader.SetSeq(1000);
//                    copyPacket->AddHeader(copyHeader);
//                    
//                    TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
//                    Ptr<Socket> copySocket = Socket::CreateSocket (GetNode (), tid);
//                    
//                    Address broadcastAddress = Ipv4Address ("10.1.1.255");
//                    uint16_t broadcastPort = 2048;
//                    
//                    if (Ipv4Address::IsMatchingType(broadcastAddress) == true){
//                        copySocket->Bind ();
//                        copySocket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(broadcastAddress), broadcastPort));
//                    }
//                    
//                    copySocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
//                    copySocket->SetAllowBroadcast (true);
//                    
//                    m_txTrace (copyPacket);
//                    copySocket->Send (copyPacket);
//                }
//                else{
////                    // broadcast a message to request the message
////                    Ptr<Ipv4L3Protocol> IPObject = GetNode()->GetObject<Ipv4L3Protocol>();
////                    char ipAddr[11];
////                    strncpy(ipAddr, "10.1.1.", 7);
////                    std::ostringstream oss;
////                    int32_t status;
////                    for(int i=1; i<=254; i++){
////                        oss << "10.1.1.";
////                        oss << i;
////                        status = IPObject->GetInterfaceForAddress(Ipv4Address (oss.str().c_str()));
////                        NS_LOG_INFO("Node " << m_nodeId << ": Interface Status = " << status);
////                        oss.str("");
////                    }
//                }
//            }
////            else if(seqNum == 10000){
////                if(!m_bReqReceived){
////                    
////                }
////            }
//            else NS_LOG_ERROR("We have a problem with the frame type!!!");
            
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            if(m_mode == 2){
                SeqTsHeader seqTs;
                seqTs.SetSeq(++seqNum);
                packet->AddHeader(seqTs);

                for(int i=0; i<(int)m_nChildSMs; i++){
                    m_txTrace(packet);
                    m_targetedSMSockets[i]->Send(packet);

                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " relayed the "
                            "Firmware Upgrade Request in size of " << packet->GetSize() << 
                            " bytes to " << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (m_targetedSMAddressList[i]).GetPort() <<
                            " at " << Simulator::Now ().GetSeconds () << " s");
                }
            }
//        
//            // call to the trace sinks before the packet is actually sent,
//            // so that tags added to the packet can be sent as well
//            m_txTrace (packet);
//            m_remoteUDPSocket->Send (packet);
            
//            NS_LOG_INFO ("Node " << GetNode()->GetId() << " re-broadcasted a Firmware Upgrade Request in size of " <<
//                    packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
        }
    }
    
    void FWUpgradeSource::HandleReadMode3 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            if(seqNum == 1000){
                m_rxCount += 1.0;
                m_nReceipts++;
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received the FWUF in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }

                m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACK, this);
                
                m_copyPacket = packet->CreateFragment(0, packet->GetSize());
                
                m_bFWUFReceived = true;
            }
            else if(seqNum == 5000){
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received an Alarm message in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }
                
                if(m_bFWUFReceived){
                    //There is a copy of the FWUF
                    Ptr<Packet> copyPacket = m_copyPacket->CreateFragment(0, m_copyPacket->GetSize());
                    SeqTsHeader copyHeader;
                    copyHeader.SetSeq(1000);
                    copyPacket->AddHeader(copyHeader);
                    
                    m_txTrace (copyPacket);
                    copySocket->Send (copyPacket);
                    
                    NS_LOG_INFO ("Node " << GetNode()->GetId() << 
                            " re-broadcasted the FWUF in size of " <<
                            packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
                }
                else{
//                    // broadcast a message to request the message
//                    Ptr<Ipv4L3Protocol> IPObject = GetNode()->GetObject<Ipv4L3Protocol>();
//                    char ipAddr[11];
//                    strncpy(ipAddr, "10.1.1.", 7);
//                    std::ostringstream oss;
//                    int32_t status;
//                    for(int i=1; i<=254; i++){
//                        oss << "10.1.1.";
//                        oss << i;
//                        status = IPObject->GetInterfaceForAddress(Ipv4Address (oss.str().c_str()));
//                        NS_LOG_INFO("Node " << m_nodeId << ": Interface Status = " << status);
//                        oss.str("");
//                    }
                }
            }
            else NS_LOG_ERROR("We have a problem with the frame type!!!");
            
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
//        
//            // call to the trace sinks before the packet is actually sent,
//            // so that tags added to the packet can be sent as well
//            m_txTrace (packet);
//            m_remoteUDPSocket->Send (packet);
            
//            NS_LOG_INFO ("Node " << GetNode()->GetId() << " re-broadcasted a Firmware Upgrade Request in size of " <<
//                    packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
        }
    }
    
    void FWUpgradeSource::HandleReadMode4 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            m_rxCount += 1.0;
            
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            
            if(seqNum == 1000){
                tmp.rxCount = 1000;
                m_nReceipts++;
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received the FWU Request in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }

                m_ACKEvent = Simulator::Schedule(NanoSeconds (430500), &FWUpgradeSource::SendACK, this);
                
                m_copyPacket = packet->CreateFragment(0, packet->GetSize());
                
                if(!m_bFWUReqReceived && m_boolTargeted){
                    Simulator::Schedule(NanoSeconds(m_procDelay), &FWUpgradeSource::InitiateFTP, this); 
                    // 820000ns (verify the signature on the SC_FWUReq) 20630000ns (designcrypt the SC_FWUReq) = 21450000ns
                    m_bFWUReqReceived = true;
                }
            }
            else if(seqNum == 5000){
                tmp.rxCount = 5000;
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received an Alarm message in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }
                
                if(m_bFWUReqReceived){
                    //There is a copy of the FWU Request
                    Ptr<Packet> copyPacket = m_copyPacket->CreateFragment(0, m_copyPacket->GetSize());
                    SeqTsHeader copyHeader;
                    copyHeader.SetSeq(1000);
                    copyPacket->AddHeader(copyHeader);
                    
                    m_txTrace (copyPacket);
                    copySocket->Send (copyPacket);
                    
                    NS_LOG_INFO ("Node " << GetNode()->GetId() << " re-broadcasted the FWU Request in size of " <<
                                 copyPacket->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
                }
                else{
                    //Do nothing!
//                    // broadcast a message to request the message
//                    Ptr<Ipv4L3Protocol> IPObject = GetNode()->GetObject<Ipv4L3Protocol>();
//                    char ipAddr[11];
//                    strncpy(ipAddr, "10.1.1.", 7);
//                    std::ostringstream oss;
//                    int32_t status;
//                    for(int i=1; i<=254; i++){
//                        oss << "10.1.1.";
//                        oss << i;
//                        status = IPObject->GetInterfaceForAddress(Ipv4Address (oss.str().c_str()));
//                        NS_LOG_INFO("Node " << m_nodeId << ": Interface Status = " << status);
//                        oss.str("");
//                    }
                }
            }
            else NS_LOG_ERROR("We have a problem with the frame type!!!");
            
            m_stat.push_back(tmp);
            
            if(m_boolTargeted)
                m_statTargetedSMs.push_back(tmp);
            else
                m_statNoNTargetedSMs.push_back(tmp);
        }
    }
    
    void FWUpgradeSource::HandleReadFTP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " downloading the FWUF: " << 
                        m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                        ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                        now.GetSeconds () << " s");
            }
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
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
    }
    
    void FWUpgradeSource::HandleReadMode5 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
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
            
            m_nReceipts++;
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received a FWUF in size of " << 
                        m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                        ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                        Simulator::Now ().GetSeconds () << " s");
            }
            
            m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACK, this);
        }
    }
    
    void FWUpgradeSource::HandleReadMode6 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
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
            
            m_nReceipts++;
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received a FWU Request in size of " << 
                        m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                        ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                        Simulator::Now ().GetSeconds () << " s");
            }
            
            if(!m_bFWUReqReceived){
                Simulator::ScheduleNow(&FWUpgradeSource::InitiateFTP, this);
                m_bFWUReqReceived = true;
            }
        }
    }
    
    void FWUpgradeSource::HandleReadMode7 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            m_rxCount += 1.0;
            
            Time now = Simulator::Now();
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            uint32_t batchIndex = seqNum - 1000;
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);
            
            std::vector<uint8_t> payload (m_decoders[batchIndex].payload_size ());
            
            packet->CopyData (&payload[0], m_decoders[batchIndex].payload_size ());
            m_decoders[batchIndex].read_payload (&payload[0]);
            
            if(m_decoders[batchIndex].is_complete ()){
//                SeqTsHeader header2;
//                Ptr<Packet> packet2 = Create<Packet> (&m_decoderBuffers[batchIndex][0], m_decoderBuffers[batchIndex].size());
//                NS_LOG_INFO("Decoder Size: " << m_decoderBuffer.size());
//                packet2->RemoveHeader(header2);
//                uint32_t seqNum2 = header2.GetSeq ();
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received Batch[" << batchIndex << 
                            "] of the FWUF in size of " << m_rxBytes << " bytes from " << 
                            InetSocketAddress::ConvertFrom (from).GetIpv4 () << ":" << 
                            InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }
                
                m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACKMode7, this, batchIndex);
            }
        }
    }
    
    void FWUpgradeSource::HandleReadMode8 (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            m_rxCount += 1.0;
            
            Time now = Simulator::Now();
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            StatRecord tmp;
            tmp.round = seqNum;
            tmp.rxCount = 1;
            tmp.rxBytes = m_rxBytes;
            tmp.totDelay = (now.ToInteger (Time::US) - txtime.ToInteger (Time::US) );
            tmp.firstRxTime = now;
            tmp.lastRxTime = now;
            tmp.minTxTime = txtime;
            m_stat.push_back(tmp);

            std::vector<uint8_t> payload (m_decoder.payload_size ());
            packet->CopyData (&payload[0], m_decoder.payload_size ());
            m_decoder.read_payload (&payload[0]);
            
            if(m_decoder.is_complete ()){
//                SeqTsHeader header2;
//                Ptr<Packet> packet2 = Create<Packet> (&m_decoderBuffers[batchIndex][0], m_decoderBuffers[batchIndex].size());
//                NS_LOG_INFO("Decoder Size: " << m_decoderBuffer.size());
//                packet2->RemoveHeader(header2);
//                uint32_t seqNum2 = header2.GetSeq ();
                if (InetSocketAddress::IsMatchingType (from)){
                    NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received a Firmware Upgrade Request in size of " << 
                            m_rxBytes << " bytes from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
                            ":" << InetSocketAddress::ConvertFrom (from).GetPort () << " at " << 
                            Simulator::Now ().GetSeconds () << " s");
                }
                
                m_ACKEvent = Simulator::Schedule(NanoSeconds (414800), &FWUpgradeSource::SendACKMode8, this);
                
                if(!m_bFWUReqReceived && m_boolTargeted){
                    Simulator::ScheduleNow(&FWUpgradeSource::InitiateFTP, this);
                    m_bFWUReqReceived = true;
                }
            }
        } 
    }
    
    void FWUpgradeSource::SendACKMode7 (uint32_t batchIndex){
        NS_LOG_FUNCTION(this);
        NS_ASSERT (m_ACKEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(4000+batchIndex);    //4000 -> ACK packet
        packet = Create<Packet> (48-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        m_txTrace(packet);
        m_ACKSocket->Send(packet);
        
        if (InetSocketAddress::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The Node " << GetNode()->GetId() << " unicasted an ACK back to the GATEWAY in "
                    "size of " << packet->GetSize() << " bytes to " << 
                    InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 () << 
                    ":" << InetSocketAddress::ConvertFrom (m_peerAddress).GetPort() << 
                    " at " << Simulator::Now ().GetSeconds () << " s");
        }
    }
    
    void FWUpgradeSource::SendACKMode8 (void){
        NS_LOG_FUNCTION(this);
        NS_ASSERT (m_ACKEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(4000);    //4000 -> ACK packet
        packet = Create<Packet> (48-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        m_txTrace(packet);
        m_ACKSocket->Send(packet);
        
        if (InetSocketAddress::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The Node " << GetNode()->GetId() << " unicasted an ACK back to the GATEWAY in "
                    "size of " << packet->GetSize() << " bytes to " << 
                    InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 () << 
                    ":" << InetSocketAddress::ConvertFrom (m_peerAddress).GetPort() << 
                    " at " << Simulator::Now ().GetSeconds () << " s");
        }
    }
    
    void FWUpgradeSource::SendACK (void){
        NS_LOG_FUNCTION(this);
        NS_ASSERT (m_ACKEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(4000);    //4000 -> ACK packet
        packet = Create<Packet> (48-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        m_txTrace(packet);
        m_ACKSocket->Send(packet);
        
        if (InetSocketAddress::IsMatchingType (m_peerAddress)){
            NS_LOG_DEBUG ("The Node " << GetNode()->GetId() << " unicasted an ACK back to the GATEWAY in "
                    "size of " << packet->GetSize() << " bytes to " << 
                    InetSocketAddress::ConvertFrom (m_peerAddress).GetIpv4 () << 
                    ":" << InetSocketAddress::ConvertFrom (m_peerAddress).GetPort() << 
                    " at " << Simulator::Now ().GetSeconds () << " s");
        }
    }
    
    void FWUpgradeSource::SendH_Up (void){
        if (!m_remoteTCPSocket){
            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
            m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);

            if (Inet6SocketAddress::IsMatchingType (m_peerAddress)){
                m_remoteTCPSocket->Bind6 ();
            }
            else if (InetSocketAddress::IsMatchingType (m_peerAddress) ||
             PacketSocketAddress::IsMatchingType (m_peerAddress)){
                m_remoteTCPSocket->Bind ();
            }

            m_remoteTCPSocket->Connect (m_peerAddress);
            m_remoteTCPSocket->SetAllowBroadcast (true);
            m_remoteTCPSocket->ShutdownRecv ();

            m_remoteTCPSocket->SetConnectCallback (
                        MakeCallback (&FWUpgradeSource::ConnectionSucceededFTP, this),
                        MakeCallback (&FWUpgradeSource::ConnectionFailedFTP, this));
        }
        
        Ptr<Packet> packet;
        
        SeqTsHeader header;
        header.SetSeq(0);
        packet = Create<Packet> (m_SCH_UpSize-(header.GetSerializedSize()));
        packet->AddHeader(header);
        
        m_txTrace (packet);
        m_remoteTCPSocket->Send (packet);
        
        NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " sent the GATEWAY a challenge in size of " <<
                    packet->GetSize() << " bytes at " << Simulator::Now ().GetSeconds () << " s");
    }
    
    void FWUpgradeSource::InitiateFTP (void){
        NS_LOG_FUNCTION(this);
        if (!m_remoteTCPSocket){
            TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
            m_remoteTCPSocket = Socket::CreateSocket (GetNode (), tid);

            if (Inet6SocketAddress::IsMatchingType (m_peerAddress)){
                m_remoteTCPSocket->Bind6 ();
            }
            else if (InetSocketAddress::IsMatchingType (m_peerAddress) ||
             PacketSocketAddress::IsMatchingType (m_peerAddress)){
                m_remoteTCPSocket->Bind ();
            }

            m_remoteTCPSocket->Connect (m_peerAddress);
            m_remoteTCPSocket->SetAllowBroadcast (true);

            m_remoteTCPSocket->SetConnectCallback (
                        MakeCallback (&FWUpgradeSource::ConnectionSucceededFTP, this),
                        MakeCallback (&FWUpgradeSource::ConnectionFailedFTP, this));
            
            m_remoteTCPSocket->SetRecvCallback (MakeCallback (&FWUpgradeSource::FTP, this));
        }
        
        if(m_mode == 4)
            m_sendEvent = Simulator::Schedule(NanoSeconds(668300), &FWUpgradeSource::SendHASH, this);
        
        NS_LOG_INFO("Node " << m_nodeId << " has started to establish a TCP connection at " << 
                Simulator::Now().GetSeconds() << " s.");
    }
    
    void FWUpgradeSource::SendHASH(void){
        NS_LOG_FUNCTION (this);
        NS_ASSERT (m_sendEvent.IsExpired ());
        
        Ptr<Packet> packet;
        SeqTsHeader header;
        header.SetSeq(0);
        packet = Create<Packet> (89-(header.GetSerializedSize()));
        packet->AddHeader(header);

        m_txTrace (packet);
        m_remoteTCPSocket->Send (packet);
        
        NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #0 FTP packet in size of " << 
                       packet->GetSize() << " to initiate the FTP protocol at " << 
                       Simulator::Now().GetSeconds() << " s");
    }
    
    void FWUpgradeSource::FTP (Ptr<Socket> socket){
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom (from))){
            Time now = Simulator::Now();
            
            uint32_t m_rxBytes = packet->GetSize();
            SeqTsHeader header;
            packet->RemoveHeader(header);
            uint32_t seqNum = header.GetSeq ();
            Time txtime = header.GetTs ();
            
            packet->RemoveAllPacketTags ();
            packet->RemoveAllByteTags ();
            
            if (InetSocketAddress::IsMatchingType (from)){
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " received some FTP data in size of " << 
                        m_rxBytes << " bytes with sequence number of " << seqNum << " from " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << 
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
            
            m_statTargetedSMs.push_back(tmp);
            
            Ptr<Packet> pack;
            SeqTsHeader header2;
            if(seqNum == 1){
                //reply with a packet of 15 bytes in size
                header2.SetSeq((uint32_t)2);
                pack = Create<Packet>(15 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #2 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #1 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 3){
                //reply with a packet of 16 bytes in size
                header2.SetSeq((uint32_t)4);
                pack = Create<Packet>(16 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #4 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #3 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 5){
                //reply with a packet of 12 bytes in size
                header2.SetSeq((uint32_t)6);
                pack = Create<Packet>(12 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #6 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #5 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 7){
                //reply with a packet of 14 bytes in size
                header2.SetSeq((uint32_t)8);
                pack = Create<Packet>(14 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #8 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #7 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 9){
                //reply with a packet of 29 bytes in size
                header2.SetSeq((uint32_t)10);
                pack = Create<Packet>(29 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #10 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #9 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 11){
                //reply with a packet of 14 bytes in size
//                Simulator::Schedule(NanoSeconds(400000000), &FWUpgradeSource::SendPacketN12, this, socket);
                header2.SetSeq((uint32_t)12);
                pack = Create<Packet>(14 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #12 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #11 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 14){
                //reply with a packet of 12 bytes in size
                header2.SetSeq((uint32_t)15);
                pack = Create<Packet>(12 - header.GetSerializedSize());
                pack->AddHeader(header2);
                m_txTrace(pack);
                socket->Send(pack);
                
                NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #15 FTP packet in size of " << 
                                    pack->GetSize() << " in response to the #14 packet " << " at " << 
                                    Simulator::Now().GetSeconds() << " s");
            }
            else if(seqNum == 13){}
            else if(seqNum == 16){
                m_completionTS = Simulator::Now();
                m_bFWUFReceived = true;
                NS_LOG_INFO("Node " << m_nodeId << " has successfully downloaded the FWUF!!!");
            }
            else NS_LOG_ERROR("We have a problem with the message type!!!");
        }
    }
    
    void FWUpgradeSource::SendPacketN12 (Ptr<Socket> socket){
        Ptr<Packet> packet;
        SeqTsHeader header;
        
        header.SetSeq((uint32_t)12);
        packet = Create<Packet>(14 - header.GetSerializedSize());
        packet->AddHeader(header);
        m_txTrace(packet);
        socket->Send(packet);

        NS_LOG_DEBUG ("Node " << GetNode()->GetId() << " has sent the #12 FTP packet in size of " << 
                            packet->GetSize() << " in response to the #11 packet " << " at " << 
                            Simulator::Now().GetSeconds() << " s");
    }
} // Namespace ns3
