/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   fw-upgrade-sink.h
 * Author: samet
 *
 * Created on October 18, 2016, 2:09 PM
 */

#ifndef FW_UPGRADE_SINK_H
#define FW_UPGRADE_SINK_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/string.h"

#include <kodocpp/kodocpp.hpp>

#include <map>

namespace ns3 {

    class Address;
    class Socket;
    class Packet;

    /**
     * \ingroup applications
     * \defgroup packetsink PacketSink
     *
     * This application was written to complement OnOffApplication, but it
     * is more general so a PacketSink name was selected.  Functionally it is
     * important to use in multicast situations, so that reception of the layer-2
     * multicast frames of interest are enabled, but it is also useful for
     * unicast as an example of how you can write something simple to receive
     * packets at the application layer.  Also, if an IP stack generates
     * ICMP Port Unreachable errors, receiving applications will be needed.
     */

    /**
     * \ingroup packetsink
     *
     * \brief Receive and consume traffic generated to an IP address and port
     *
     * This application was written to complement OnOffApplication, but it
     * is more general so a PacketSink name was selected.  Functionally it is
     * important to use in multicast situations, so that reception of the layer-2
     * multicast frames of interest are enabled, but it is also useful for
     * unicast as an example of how you can write something simple to receive
     * packets at the application layer.  Also, if an IP stack generates
     * ICMP Port Unreachable errors, receiving applications will be needed.
     *
     * The constructor specifies the Address (IP address and port) and the
     * transport protocol to use.   A virtual Receive () method is installed
     * as a callback on the receiving socket.  By default, when logging is
     * enabled, it prints out the size of packets and their address, but
     * we intend to also add a tracing source to Receive() at a later date.
     */
    class FWUpgradeSink : public Application{
        public:
            static TypeId GetTypeId (void);
            FWUpgradeSink ();
            FWUpgradeSink (uint16_t port, Address local, uint32_t delay);
            FWUpgradeSink(kodocpp::codec codeType, kodocpp::field field,
                          uint32_t generationSize, uint32_t packetSize);
            FWUpgradeSink(kodocpp::codec codeType, kodocpp::field field,
                          uint32_t generationSize, uint32_t packetSize,
                          uint32_t batchSize);

            virtual ~FWUpgradeSink ();

            void ReportStat (std::ostream & os);

            /**
            * \return the total bytes received in this sink app
            */
            uint32_t GetTotalRx () const;

            /**
            * \return pointer to listening socket
            */
            Ptr<Socket> GetListeningSocket (void) const;

            /**
            * \return list of pointers to accepted sockets
            */
            std::list<Ptr<Socket> > GetAcceptedSockets (void) const;
            
            void SetTargetedSMAddress (Address address);
            Address GetTargetedSMAddress (uint32_t index);

        protected:
            virtual void DoDispose (void);
            
        private:
            // inherited from Application base class.
            virtual void StartApplication (void);    // Called at time specified by Start
            virtual void StopApplication (void);     // Called at time specified by Stop

            void SendMode0 (void);
            void SendMode1 (void);
            void SendMode2 (void);
            void SendMode3 (void);
            void SendMode4 (void);
            void SendMode5 (void);
            void SendMode6 (void);
            void SendMode7 (void);
            void SendMode8 (void);
            void SendPacketN1(Ptr<Socket> socket);
            void SendPacketN14(Ptr<Socket> socket);
            
            void Alarm (void);
            void ReTX(Ptr<Socket> socket, Ptr<Packet> packet, int index);
            void HandleACK(Ptr<Socket> socket);
            void HandleACKMode4(Ptr<Socket> socket);
            void HandleACKMode5(Ptr<Socket> socket);
            void HandleACKMode7(Ptr<Socket> socket);
            void HandleACKMode8(Ptr<Socket> socket);
            void SetDelayFlag(void);

            void HandleReadUDP (Ptr<Socket>);
            void HandleReadTCP (Ptr<Socket> socket);
            void HandleReadMode4 (Ptr<Socket> socket);
            void HandleReadTCPConn2 (Ptr<Socket> socket);
            void HandleACKandFTP (Ptr<Socket> socket);
            void HandleFTPMode8 (Ptr<Socket> socket);
            void EchoPacket(Ptr<Packet>);
            void SendToTarget(Ptr<Packet>);
            void SendToTargetSocket(Ptr<Packet> packet, Ptr<Socket> socket);
            void HandleAcceptMode4 (Ptr<Socket>, const Address& from);
            void HandleAcceptTCPConn2 (Ptr<Socket>, const Address& from);
            void HandleAcceptTCPMode8 (Ptr<Socket>, const Address& from);
            void HandleAcceptACKandFTP (Ptr<Socket>, const Address& from);
            void HandlePeerClose (Ptr<Socket>);
            void HandlePeerError (Ptr<Socket>);
            void HandleReport (Ptr<Packet> pkt, Address from, Ptr<Socket> socket);
            bool IsThereAnyPreviousStoredPacket(Address from);
            void StatPrint ();
            void PrintStats();
            void PrintStatsMode4();
            void PrintStatsMode6();
            void PrintStatsMode8();
            void AverageValues();

            void SendPacket (uint32_t seqNum);
            void SendUDPPacket ();
            void ConnectionSucceeded (Ptr<Socket> socket);
            void ConnectionFailed (Ptr<Socket> socket);

            void CancelEvents ();

            struct DataWaitingPacket {
                  Address from;
                  Ptr<Packet> pkt;
            };

            struct StatRecord {
                  uint16_t round;
                  uint32_t rxCount;
                  uint32_t rxBytes;
                  uint32_t totDelay;
                  Time     firstRxTime;
                  Time     lastRxTime;
                  Time     minTxTime;
            };

            // In the case of TCP, each socket accept returns a new socket, so the
            // listening socket is stored separately from the accepted sockets
            Ptr<Socket>     m_socket;       // Listening socket
            Ptr<Socket>     m_localTCPsocket;
            Ptr<Socket>     m_remoteTCPSocket; //!< Socket
            uint16_t m_UDPPort; //!< Port on which we listen for incoming packets.
            Ptr<Socket> m_UDPsocket; //!< IPv4 Socket
            Ptr<Socket> m_ACKsocket;
            Ptr<Socket> m_UDPsocket6; //!< IPv6 Socket
            Ptr<Socket> *m_targetedSMSockets;
            Address m_UDPlocal; //!< local multicast address
            std::list<Ptr<Socket> > m_socketList; //the accepted sockets
            std::list<Ptr<Socket> > m_targetSockets; //the accepted sockets
            std::vector<DataWaitingPacket> m_waitingPacket;
            std::vector<StatRecord> m_stat;
            std::vector<StatRecord> m_unicasts;
            std::vector<StatRecord> m_broadcasts;
            std::vector< Address > m_targetedSMAddressList;
            StatRecord m_initialBroadcast;
            std::vector<Address> m_targets;

            typedef std::map< uint32_t, Time > MeterSeqNumMap;
            MeterSeqNumMap m_SocketAddressMap;
            
            typedef std::map< uint32_t, Time > IPTSMap;
            IPTSMap m_IpTimeStampMap;
            std::vector < IPTSMap > m_IpTimeStampMaps;
            
            typedef std::map< uint32_t, EventId > IPEventIdMap;
            IPEventIdMap m_IpEventIdMap;

            Address         m_local;        // Local address to bind to
            Address         m_localAddress;
            Address         m_target;        // Local address to bind to
            Address         m_UDPTarget;
            Address         m_peerAddress;
            bool            m_connected;    // True if connected
            Ptr<Socket>     m_targetSocket;       // Associated socket
            Ptr<Socket>     m_UDPTargetSocket;       // Associated socket
            uint32_t        m_totalRx;      // Total bytes received
            uint32_t        m_totBytes;     // Total bytes sent so far
            EventId         m_sendEvent;    // Eventid of pending "send packet" event
            EventId         m_alarmEvent;    // Eventid of pending "send packet" event
            EventId         m_reTXEvent;    // Eventid of pending "send packet" event
            TypeId          m_tid;          // Protocol TypeId
            Time            m_lastStartTime; // Time last packet sent
            Time            m_firstSendingTime;
            Time            m_completionTS;
            uint32_t        m_serviceMessageSize; //!< Size of the sent packet (including the SeqTsHeader)
            Time            m_serviceMessageInterval; //!< Packet inter-send time
            TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
            TracedCallback<Ptr<const Packet> > m_txTrace;
            uint32_t        m_SCH_Up; // default size of receiving packet
            uint16_t        m_peerPort;
            uint32_t        m_REQSignatureSize;
            uint32_t        m_seqnum;
            uint32_t        m_procDelay;
            uint32_t        m_childNum;
            uint32_t        m_leafMeters;
            uint32_t        m_meterType;
            uint32_t        m_mode;
            uint32_t        m_scenario;
            uint32_t        m_operationId;
            uint32_t        m_nSMs;
            uint32_t        m_nChildSMs;
            uint32_t        m_nTargetedSMs;
            double          m_rxCount;
            uint32_t        m_nRecACKs;
            uint32_t        m_nodeId;
            uint32_t        m_DCRLMode;
            std::string     m_outputFilename;
            uint8_t         m_multTargetFlag;
            double          m_activeTP;
            Time            m_firstSendTime;
            bool            m_bDelayFlag;
            uint32_t        m_batchCounter;
            
////////////////////////////////Network Coding//////////////////////////////////
            
            kodocpp::codec m_codeType;
            kodocpp::field m_field;
            uint32_t m_generationSize;
            uint32_t m_packetSize;
            uint32_t m_nBatches;
            
            kodocpp::encoder m_encoder;
            std::vector<uint8_t> m_encoderBuffer;
            std::vector< kodocpp::encoder > m_encoders;
            std::vector< std::vector<uint8_t> > m_encoderBuffers;

            std::vector<uint8_t> m_payload;
            std::vector< std::vector<uint8_t> > m_payloads;
            uint32_t m_transmissionCount;
    };

} // namespace ns3

#endif /* FW_UPGRADE_SINK_H */

