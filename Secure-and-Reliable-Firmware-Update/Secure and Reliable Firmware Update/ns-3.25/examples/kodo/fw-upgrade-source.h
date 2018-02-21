/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   fw-upgrade-source.h
 * Author: samet
 *
 * Created on October 18, 2016, 2:09 PM
 */

#ifndef FW_UPGRADE_SOURCE_H
#define FW_UPGRADE_SOURCE_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/traced-callback.h"

#include <kodocpp/kodocpp.hpp>
//#include <storage/storage.hpp>

namespace ns3 {
    class Socket;
    class Packet;

    /**
     * \ingroup udpecho
     * \brief A Udp Echo client
     *
     * Every packet sent should be returned by the server and received here.
     */
    class FWUpgradeSource : public Application{
        public:
            /**
            * \brief Get the type ID.
            * \return the object TypeId
            */
            static TypeId GetTypeId (void);

            FWUpgradeSource ();
            FWUpgradeSource(kodocpp::codec codeType, kodocpp::field field,
                            uint32_t generationSize, uint32_t packetSize);
            FWUpgradeSource(kodocpp::codec codeType, kodocpp::field field,
                            uint32_t generationSize, uint32_t packetSize,
                            uint32_t batchSize);

            virtual ~FWUpgradeSource ();

            /**
            * \brief set the remote address and port
            * \param ip remote IPv4 address
            * \param port remote port
            */
            void SetRemote (Ipv4Address ip, uint16_t port);
            /**
            * \brief set the remote address and port
            * \param ip remote IPv6 address
            * \param port remote port
            */
            void SetRemote (Ipv6Address ip, uint16_t port);
            /**
            * \brief set the remote address and port
            * \param ip remote IP address
            * \param port remote port
            */
            void SetRemote (Address ip, uint16_t port);

            /**
            * Set the data size of the packet (the number of bytes that are sent as data
            * to the server).  The contents of the data are set to unspecified (don't
            * care) by this call.
            *
            * \warning If you have set the fill data for the echo client using one of the
            * SetFill calls, this will undo those effects.
            *
            * \param dataSize The size of the echo data you want to sent.
            */
            void SetDataSize (uint32_t dataSize);

            /**
            * Get the number of data bytes that will be sent to the server.
            *
            * \warning The number of bytes may be modified by calling any one of the 
            * SetFill methods.  If you have called SetFill, then the number of 
            * data bytes will correspond to the size of an initialized data buffer.
            * If you have not called a SetFill method, the number of data bytes will
            * correspond to the number of don't care bytes that will be sent.
            *
            * \returns The number of data bytes.
            */
            uint32_t GetDataSize (void) const;

            /**
            * Set the data fill of the packet (what is sent as data to the server) to 
            * the zero-terminated contents of the fill string string.
            *
            * \warning The size of resulting echo packets will be automatically adjusted
            * to reflect the size of the fill string -- this means that the PacketSize
            * attribute may be changed as a result of this call.
            *
            * \param fill The string to use as the actual echo data bytes.
            */
            void SetFill (std::string fill);

            /**
            * Set the data fill of the packet (what is sent as data to the server) to 
            * the repeated contents of the fill byte.  i.e., the fill byte will be 
            * used to initialize the contents of the data packet.
            * 
            * \warning The size of resulting echo packets will be automatically adjusted
            * to reflect the dataSize parameter -- this means that the PacketSize
            * attribute may be changed as a result of this call.
            *
            * \param fill The byte to be repeated in constructing the packet data..
            * \param dataSize The desired size of the resulting echo packet data.
            */
            void SetFill (uint8_t fill, uint32_t dataSize);

            /**
            * Set the data fill of the packet (what is sent as data to the server) to
            * the contents of the fill buffer, repeated as many times as is required.
            *
            * Initializing the packet to the contents of a provided single buffer is 
            * accomplished by setting the fillSize set to your desired dataSize
            * (and providing an appropriate buffer).
            *
            * \warning The size of resulting echo packets will be automatically adjusted
            * to reflect the dataSize parameter -- this means that the PacketSize
            * attribute of the Application may be changed as a result of this call.
            *
            * \param fill The fill pattern to use when constructing packets.
            * \param fillSize The number of bytes in the provided fill pattern.
            * \param dataSize The desired size of the final echo data.
            */
            void SetFill (uint8_t *fill, uint32_t fillSize, uint32_t dataSize);
            
            void SetTargetedSMAddress (Address address);
            Address GetTargetedSMAddress (uint32_t index);

        protected:
            virtual void DoDispose (void);

        private:
            virtual void StartApplication (void);
            virtual void StopApplication (void);
            void ConnectionSucceededFTP (Ptr<Socket> socket);
            void ConnectionFailedFTP (Ptr<Socket> socket);
            
            void HandlePeerClose (Ptr<Socket> socket);
            void HandlePeerError (Ptr<Socket> socket);
            void HandleAccept (Ptr<Socket> s, const Address& from);
            
            void PrintStats(void);
            void PrintStatsMode4(void);
            void PrintStatsMode6(void);
            void PrintStatsMode8(void);
            void AverageValues(void);

            /**
            * \brief Schedule the next packet transmission
            * \param dt time interval between packets.
            */
            void ScheduleTransmit (Time dt);
            /**
            * \brief Send a packet
            */
            void Send (void);
            void SendPacketN12 (Ptr<Socket> socket);
            
            void SendH_Up (void);
            void InitiateFTP (void);
            void SendACK (void);
            void SendACKMode7 (uint32_t batchIndex);
            void SendACKMode8 (void);
            void SendHASH(void);

            /**
            * \brief Handle a packet reception.
            *
            * This function is called by lower layers.
            *
            * \param socket the socket the packet was received to.
            */
            void HandleRead (Ptr<Socket> socket);
            void HandleReadMode3 (Ptr<Socket> socket);
            void HandleReadMode4 (Ptr<Socket> socket);
            void HandleReadMode5 (Ptr<Socket> socket);
            void HandleReadMode6 (Ptr<Socket> socket);
            void HandleReadMode7 (Ptr<Socket> socket);
            void HandleReadMode8 (Ptr<Socket> socket);
            void HandleReadFTP (Ptr<Socket> socket);
            
            void FTP (Ptr<Socket> socket);
            
            struct StatRecord {
                  uint16_t round;
                  uint32_t rxCount;
                  uint32_t rxBytes;
                  uint32_t totDelay;
                  Time     firstRxTime;
                  Time     lastRxTime;
                  Time     minTxTime;
            };

            uint32_t m_count; //!< Maximum number of packets the application will send
            uint32_t m_nChildSMs;
            uint32_t m_nSMs;
            bool m_boolTargeted;
            uint32_t m_nTargetedSMs;
            Time m_interval; //!< Packet inter-send time
            Time m_connReqPeriod;
            Time m_completionTS;
            uint32_t m_size; //!< Size of the sent packet
            std::vector<StatRecord> m_stat;
            std::vector<StatRecord> m_statTargetedSMs;
            std::vector<StatRecord> m_statNoNTargetedSMs;
            
            uint32_t m_procDelay;

            uint32_t m_dataSize; //!< packet payload size (must be equal to m_size)
            uint8_t *m_data; //!< packet payload data

            uint32_t m_sent; //!< Counter for sent packets
            Ptr<Socket> m_ACKSocket; //!< Socket
            Ptr<Socket> m_socket; //!< Socket
            Ptr<Socket> copySocket;
            Ptr<Socket> m_remoteUDPSocket; //!< Socket
            Ptr<Socket> m_remoteTCPSocket; //!< Socket
            Ptr<Socket> m_localTCPsocket;
            Ptr<Packet> m_copyPacket;
            Address m_peerAddress; //!< Remote peer address
            uint16_t m_peerPort; //!< Remote peer port
            uint32_t m_SCH_UpSize;
            double m_activeTP;
            Time m_firstSendTime;
            EventId m_sendEvent; //!< Event to send the next packet
            EventId m_ACKEvent; //!< Event to send the next packet

            /// Callbacks for tracing the packet Tx events
            TracedCallback<Ptr<const Packet> > m_txTrace;

            int64_t m_tSent;
            int64_t m_tReceived;
            bool m_connected;
            bool m_challengeSent;
            bool m_bFWUReqReceived;
            bool m_bFWUFReceived;
            double m_rxCount;
            uint32_t m_nodeId;
            
            Address m_local; //!< local multicast address
            
            Ptr<Socket> *m_targetedSMSockets;
            std::vector< Address > m_targetedSMAddressList;
            
            uint32_t m_mode;
            
            std::vector<double> m_AvEtoEDelays;
            std::vector<double> m_Throughputs;
            
////////////////////////////////Network Coding//////////////////////////////////            
            kodocpp::codec m_codeType;
            kodocpp::field m_field;
            uint32_t m_generationSize;
            uint32_t m_packetSize;
            uint32_t m_nBatches;
            
            kodocpp::decoder m_decoder;
            std::vector<uint8_t> m_decoderBuffer;
            std::vector< kodocpp::decoder > m_decoders;
            std::vector< std::vector<uint8_t> > m_decoderBuffers;
    };
} // namespace ns3

#endif /* FW_UPGRADE_SOURCE_H */

