/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008,2009 IITP RAS
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
 * Author: Kirill Andreev <andreev@iitp.ru>
 *
 *
 * By default this script creates m_xSize * m_ySize square grid topology with
 * IEEE802.11s stack installed at each node with peering management
 * and HWMP protocol.
 * The side of the square cell is defined by m_step parameter.
 * When topology is created, UDP ping is installed to opposite corners
 * by diagonals. packet size of the UDP ping and interval between two
 * successive packets is configurable.
 *
 *  m_xSize * step
 *  |<--------->|
 *   step
 *  |<--->|
 *  * --- * --- * <---Ping sink  _
 *  | \   |   / |                ^
 *  |   \ | /   |                |
 *  * --- * --- * m_ySize * step |
 *  |   / | \   |                |
 *  | /   |   \ |                |
 *  * --- * --- *                _
 *  ^ Ping source
 *
 *  See also MeshTest::Configure to read more about configurable
 *  parameters.
 */


#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/mobility-module.h>
#include <ns3/config-store-module.h>
#include <ns3/wifi-module.h>
#include <ns3/internet-module.h>
#include <ns3/mesh-module.h>
#include <ns3/log.h>
//#include <ns3/applications-module.h>

// Simulation includes
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <ctime>
#include <sstream>
#include <fstream>

#include <stdio.h>      /* printf, NULL */
#include <stdlib.h>     /* srand, rand */
#include <time.h>

// Kodo includes
#include "kodo-broadcast.h"

#include "fw-upgrade-sink.h"
#include "fw-upgrade-source.h"

#include "n_eq_coord.h"
#include "n_eq_25.h"
#include "n_eq_36.h"
#include "n_eq_49.h"
#include "n_eq_64.h"
#include "n_eq_81.h"
#include "n_eq_100.h"
#include "n_eq_121.h"
#include "n_eq_144.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("SM_FW_Upgrade");

struct SM {
    uint32_t nodeId;
    uint32_t nChildNodes;
    struct SM *parent;
    struct SM ** childNodes;
};

typedef struct SM NodeStr;
typedef struct SM *NodePtr;

NodePtr root;
NodePtr *allNodes;

class MeshTest{
    public:
        
        uint32_t  m_mode;
        /// Init test
        MeshTest ();
        
        /// Configure test from command line arguments
        void Configure (int argc, char ** argv);
        void ReadMST();
        
        /// Run test
        int Run ();
    private:
        int       m_xSize;
        int       m_ySize;
        double    m_step;
        double    m_randomStart;
        double    m_totalTime;
        double    m_packetInterval;
        uint32_t  m_nLeafSMs;
        uint16_t  m_packetSize;
        uint32_t  m_nIfaces;
        int64_t   m_streamIndex;
        int       m_nVehicles;
        int       m_nVehiclesPerMeter;
        int       m_nNodes;
        bool      m_chan;
        bool      m_pcap;
        bool      m_gridtopology;
        bool      m_singleVehicle;
        int       m_topoID;
        int       m_sinkID;
        int       m_targetedSMs[10];
        int       m_omnID;
        int       m_regionID;
        double    m_meterHeight;
        int       m_nChosenMeters;
        double    m_connReqPeriod;
        double    m_waveInterval;
        double    m_serviceMessageInterval;
        std::string m_stack;
        std::string m_root;
        std::string m_fMST;
        uint32_t m_scenario;
        uint32_t m_velocity;
        uint32_t m_SMDelay;  
        uint32_t m_GWDelay;
        double    m_tFirstSending;
        double m_initstart;
        uint32_t m_SCH_UpSize;
        uint32_t m_REQSignatureSize;

        std::ofstream m_os;

        vector< coordinates > nodeCoords;
        bool * indexChecks;
        int ** regionIDs;
        
        vector< int > leafSMIndices;
        vector< int > parentOfLeafSMIndices;
        vector< int > intermediateSMIndices;
        vector< int > parentOfIntermediateSMIndices;
        vector< int > count;
        vector< int > psize;
        vector< int > fheAggTimes;

        //to calculate the length of the simulation
        float m_timeTotal, m_timeStart, m_timeEnd;

        /// List of network nodes
        NodeContainer meshNodes;
        
        /// List of all mesh point devices
        NetDeviceContainer meshDevices;
        
        //Addresses of interfaces:
        Ipv4InterfaceContainer meshInterfaces;
        
        // MeshHelper. Report is not static methods
        MeshHelper mesh;
        
    private:
        /// Create nodes and setup their mobility
        void CreateNodes();
        void CreateDevices();
        void ConfigureMobility();
        void AssignChosenNodes(int number);
        
        /// Install internet m_stack on nodes
        void InstallInternetStack ();
        void InstallStaticRoutes ();
        
        /// Install applications
        void InstallApplicationMode0 ();
        void InstallApplicationMode1 ();
        void InstallApplicationMode2 ();
        void InstallApplicationMode3 ();
        void InstallApplicationMode4 ();
        void InstallApplicationMode5 ();
        void InstallApplicationMode6 ();
        void InstallApplicationMode7 ();
        void InstallApplicationMode8 ();

        /// Print mesh devices diagnostics
        void Report ();
        Vector GetPosition (Ptr<Node> node);
        void traverseATree(NodePtr node);
};

MeshTest::MeshTest () :
    m_mode (1),
    m_xSize (6),
    m_ySize (6),
    m_step (115.0),
    m_randomStart (0.1),
    m_totalTime (100),
    m_packetInterval (0.1),
    m_packetSize (80),
    m_nIfaces (1),
    m_streamIndex (0),
    m_nVehicles (40),
    m_nVehiclesPerMeter (4),
    m_nNodes (81),
    m_chan (true),
    m_pcap (false),
    m_gridtopology (false),
    m_singleVehicle (true),
    //46 1 22 3
    m_topoID (46),
    m_sinkID (1),
    m_omnID (75),
    m_regionID (3),
    m_meterHeight (0.0),
    m_nChosenMeters (10),
    m_connReqPeriod (2.0),
    m_waveInterval (0.1),
    m_serviceMessageInterval (5.0),
    m_stack ("ns3::Dot11sStack"),
    m_root ("00:00:00:00:00:02"),  //m_root ("00:00:00:00:00:06")
    m_fMST ("MST-36-46-1.mst"),
    m_scenario (1),
    m_velocity (40),
    m_SMDelay (55837000),
    m_GWDelay (20000000),
    m_tFirstSending (22.0),
    m_initstart (10.0),
    m_SCH_UpSize (93),
    m_REQSignatureSize (97){}

void MeshTest::Configure (int argc, char *argv[]){
    CommandLine cmd;
    cmd.AddValue ("x-size", "Number of nodes in a row grid. [6]", m_xSize);
    cmd.AddValue ("y-size", "Number of rows in a grid. [6]", m_ySize);
    cmd.AddValue ("step",   "Size of edge in our grid, meters. [100 m]", m_step);
    /*
     * As soon as starting node means that it sends a beacon,
     * simultaneous start is not good.
     */
    cmd.AddValue ("start",  "Maximum random start delay, seconds. [0.1 s]", m_randomStart);
    cmd.AddValue ("time",  "Simulation time, seconds [100 s]", m_totalTime);
    cmd.AddValue ("packet-interval",  "Interval between packets in UDP ping, seconds [0.001 s]", m_packetInterval);
    cmd.AddValue ("packet-size",  "Size of packets in UDP ping", m_packetSize);
    cmd.AddValue ("interfaces", "Number of radio interfaces used by each mesh point. [1]", m_nIfaces);
    cmd.AddValue ("channels",   "Use different frequency channels for different interfaces. [0]", m_chan);
    cmd.AddValue ("pcap",   "Enable PCAP traces on interfaces. [0]", m_pcap);
    cmd.AddValue ("grid", "Choice whether grid or random topology [false]", m_gridtopology);
    cmd.AddValue ("sVehicle", "Choice whether only one vehicle or multiple vehicles [true]", m_singleVehicle);
    cmd.AddValue ("nVehicles", "Number of vehicles", m_nVehicles);
    cmd.AddValue ("nVehiclesPM", "Number of vehicles per meter", m_nVehiclesPerMeter);
    cmd.AddValue ("topoID", "Topology ID", m_topoID);
    cmd.AddValue ("sinkID", "Sink ID", m_sinkID);
//    cmd.AddValue ("targetedSMs", "Index of Targeted SMs", m_targetedSMs);
    cmd.AddValue ("mst", "Topology file to read in node positions", m_fMST);
    cmd.AddValue ("omnID", "Othermost Node ID", m_omnID);
    cmd.AddValue ("regionID", "Region ID", m_regionID);
    cmd.AddValue ("zCoord", "Meter height", m_meterHeight);
    cmd.AddValue ("smDelay", "SM delay", m_SMDelay);
    cmd.AddValue ("gwDelay", "GW delay", m_GWDelay);
    cmd.AddValue ("fSendingT", "First sending time", m_initstart);
    cmd.AddValue ("nChosenMs", "Number of chosen meters", m_nChosenMeters);
    cmd.AddValue ("connRP", "Connection request period", m_connReqPeriod);
    cmd.AddValue ("waveInt", "WAVE message interval", m_waveInterval);
    cmd.AddValue ("serviceMInt", "Service message interval", m_serviceMessageInterval);
    cmd.AddValue ("mode", "D-CRL mode on or off", m_mode);
    cmd.AddValue ("stack",  "Type of protocol stack. ns3::Dot11sStack by default", m_stack);
    cmd.AddValue ("root", "Mac address of root mesh point in HWMP", m_root);
    cmd.AddValue ("scenario", "EV certificate verification scenario", m_scenario);
    cmd.AddValue ("velocity", "EV certificate verification scenario", m_velocity);
    cmd.AddValue ("challenge-size", "The size of signcrypted challenge in bytes", m_SCH_UpSize);
    cmd.AddValue ("fwu-request-size", "The size of firmware upgrade request in bytes", m_REQSignatureSize);

    cmd.Parse (argc, argv);
    NS_LOG_DEBUG ("Grid:" << m_xSize << "*" << m_ySize);
    NS_LOG_DEBUG ("Simulation time: " << m_totalTime << " s");
    
    for(int i=0; i<10; i++){
        m_targetedSMs[i] = atoi(argv[(i+1)]);
        NS_LOG_DEBUG("x[" << (i+1) << "] = " << m_targetedSMs[i]);
    }
}

void MeshTest::ReadMST (){
    m_nNodes = m_ySize*m_xSize;
    
    std::ifstream input;
    NS_LOG_INFO("Input File: " << m_fMST);
    input.open(("MSTs/" + m_fMST).c_str());
    
    if (input.is_open()){
        allNodes = (NodePtr *)calloc(m_nNodes, sizeof(NodePtr));
        
        for(int i=0; i<m_nNodes; i++){
            allNodes[i] = (NodePtr)malloc(sizeof(NodeStr));
            allNodes[i]->nodeId = i;
            allNodes[i]->parent = NULL;
            allNodes[i]->nChildNodes = 0;
        }
        
        root = allNodes[m_sinkID];
        
        //int j = 0;
        std::string line;

        getline (input,line);
        getline (input,line);

        int counter = atoi(line.c_str());

        m_nLeafSMs = counter;

        getline (input,line);

        int readValue = 0;

        //Indices of leaf meters
        for(int i=0; i<counter; ++i){
            //input >> child[i];
            getline (input,line);
            readValue = atoi(line.c_str());
            leafSMIndices.push_back(readValue);
        }

//        m_sensor = leafSMIndices.size();

        getline (input,line);
        getline (input,line);
        getline (input,line);

        counter = atoi(line.c_str());

        getline (input,line);

        //Indices of parents of leaf meters
        for(int i=0; i<counter; ++i){
            getline (input,line);
            readValue = atoi(line.c_str());
//            NS_LOG_INFO("Leaf Index: " << leafSMIndices[i] << " Read Value: " << readValue);
            parentOfLeafSMIndices.push_back(readValue);
            allNodes[leafSMIndices[i]]->parent = allNodes[parentOfLeafSMIndices[i]];
        }

        getline (input,line);
        getline (input,line);
        getline (input,line);

        counter = atoi(line.c_str());

        getline (input,line);

        for(int i=0; i<counter; ++i){
            getline (input,line);
            readValue = atoi(line.c_str());
            intermediateSMIndices.push_back(readValue);
        }

//        m_aggregator = intermediateSMIndices.size();

        getline (input,line);
        getline (input,line);
        getline (input,line);

        counter = atoi(line.c_str());

        getline (input,line);

        for(int i=0; i<counter; ++i){
            getline (input,line);
            readValue = atoi(line.c_str());
            parentOfIntermediateSMIndices.push_back(readValue);
            allNodes[intermediateSMIndices[i]]->parent = allNodes[parentOfIntermediateSMIndices[i]];
        }

        getline (input,line);
        getline (input,line);
        getline (input,line);

        uint32_t child_count = atoi(line.c_str());
        root->childNodes = (NodePtr *)calloc(child_count, sizeof(NodePtr));
        root->nChildNodes = child_count;

        getline (input,line);
        getline (input,line);
        getline (input,line);

        counter = atoi(line.c_str());

        getline (input,line);

        for(int i=0; i<counter; ++i){
            getline (input,line);
            readValue = atoi(line.c_str());
            count.push_back(readValue);
            allNodes[intermediateSMIndices[i]]->childNodes = (NodePtr *)calloc(readValue, sizeof(NodePtr));
            allNodes[intermediateSMIndices[i]]->nChildNodes = readValue;
        }

        getline (input,line);
        getline (input,line);
        getline (input,line);

        counter = atoi(line.c_str());

        getline (input,line);

        for(int i=0; i<counter; ++i){
            getline (input,line);
            readValue = atoi(line.c_str());
            psize.push_back(readValue);
        }
        input.close();
    } else {
        std::cerr << "Error: Can't open file " << m_fMST << "\n";
        exit (EXIT_FAILURE);
    }
    
    int k;
    for(int i=0; i<m_nNodes; i++){
        k = 0;
        for(int j=0; j<m_nNodes; j++){
            if(allNodes[j]->parent != NULL){
                if(allNodes[i] == allNodes[j]->parent){
                    allNodes[i]->childNodes[k] = allNodes[j];
                    k++;
                }
            }
        }
    }
    
    traverseATree(root);
}

void MeshTest::traverseATree(NodePtr node) {
    NS_LOG_FUNCTION(this << node);
    
    NS_LOG_INFO("Node# " << node->nodeId);
    
    for(int i=0; i<(int)node->nChildNodes; i++){
        NS_LOG_INFO("traverseATree will be called with the Node " << 
                node->childNodes[i]->nodeId << " which is child of the Node " << node->nodeId);
        traverseATree(node->childNodes[i]);
    }
}

void MeshTest::CreateNodes (){
////////////////////////////////////MESH////////////////////////////////////////
    m_nNodes = m_ySize*m_xSize;
    meshNodes.Create (m_nNodes);

    double m_txpower = 18.0; // 18dbm

    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
    wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue (-89.0) );
    wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-62.0) );
    wifiPhy.Set ("TxGain", DoubleValue (1.0) );
    wifiPhy.Set ("RxGain", DoubleValue (1.0) );
    wifiPhy.Set ("TxPowerLevels", UintegerValue (1) );
    wifiPhy.Set ("TxPowerEnd", DoubleValue (m_txpower) );
    wifiPhy.Set ("TxPowerStart", DoubleValue (m_txpower) );
    wifiPhy.Set ("RxNoiseFigure", DoubleValue (7.0) );

    // Configure YansWifiChannel
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();;
    Ptr<YansWifiChannel> channel = wifiChannel.Create ();

    wifiPhy.SetChannel (channel);
    wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11);

    // Configure the parameters of the Peer Link
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxBeaconLoss", UintegerValue (20));
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxRetries", UintegerValue (4));
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxPacketFailure", UintegerValue (5));

    // Configure the parameters of the HWMP
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPnetDiameterTraversalTime", TimeValue (Seconds (2)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPactivePathTimeout", TimeValue (Seconds (100)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPactiveRootTimeout", TimeValue (Seconds (100)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPmaxPREQretries", UintegerValue (5));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::UnicastPreqThreshold",UintegerValue (10));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::UnicastDataThreshold",UintegerValue (5));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::DoFlag", BooleanValue (true));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::RfFlag", BooleanValue (false));
    
//    Config::SetDefault ("ns3::ArpCache::WaitReplyTimeout", TimeValue (Seconds (4)));
    
    /*
    * Create mesh helper and set stack installer to it
    * Stack installer creates all needed protocols and install them to
    * mesh point device
    */
    mesh = MeshHelper::Default ();
    if (!Mac48Address (m_root.c_str ()).IsBroadcast ())
        mesh.SetStackInstaller (m_stack, "Root", Mac48AddressValue (Mac48Address (m_root.c_str ())));
    else
        //If root is not set, we do not use "Root" attribute, because it
        //is specified only for 11s
        mesh.SetStackInstaller (m_stack);
    
    if (m_chan)
        mesh.SetSpreadInterfaceChannels (MeshHelper::SPREAD_CHANNELS);
    else
        mesh.SetSpreadInterfaceChannels (MeshHelper::ZERO_CHANNEL);

    mesh.SetStandard (WIFI_PHY_STANDARD_80211g);
    mesh.SetMacType ("RandomStart", TimeValue (Seconds (m_randomStart)));
    mesh.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode",
                                  StringValue ("ErpOfdmRate6Mbps"), "RtsCtsThreshold",
                                  UintegerValue (2500));
    
    // Set number of interfaces - default is single-interface mesh point
    mesh.SetNumberOfInterfaces (m_nIfaces);
    
    // Install protocols and return container if MeshPointDevices
    meshDevices = mesh.Install (wifiPhy, meshNodes);
    
//    NS_LOG_INFO("EV MAC Address: " << devices11p.Get(0)->GetAddress());

//    for(int i=0; i<m_nNodes; i++){
//        NS_LOG_INFO("Meter " << (i+1) << " MAC Address: " << meshDevices.Get(i)->GetAddress());
//    }
//
////    for(int i=0; i<m_nChosenMeters; i++)
////        NS_LOG_INFO("Initial values of a vector: " << chosenMeterIDs[i]);
//
//    regionIDs = (int**)calloc(m_nChosenMeters, sizeof(int*));
//    for(int i=0; i<m_nChosenMeters; i++){
//        regionIDs[i] = (int*)calloc(m_nVehiclesPerMeter, sizeof(int));
//    }
//
    
//    chosenMeterIDs[0] = 10;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[0]));
//    chosenMeterIDs[1] = 11;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[1]));
//    chosenMeterIDs[2] = 2;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[2]));
//    chosenMeterIDs[3] = 13;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[3]));
//    chosenMeterIDs[4] = 40;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[4]));
//    chosenMeterIDs[5] = 50;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[5]));
//    chosenMeterIDs[6] = 41;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[6]));
//    chosenMeterIDs[7] = 0;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[7]));
//    chosenMeterIDs[8] = 33;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[8]));
//    chosenMeterIDs[9] = 79;
//    meshToVANETNodes.Add(meshNodes.Get(chosenMeterIDs[9])); 
    
    srand (time(NULL));
    AssignChosenNodes(m_nChosenMeters);
//
//    for(int i=0; i<m_nChosenMeters; i++){
//        for(int j=0; j<m_nVehiclesPerMeter; j++){
//            regionIDs[i][j] = (j%4)+1;
////            NS_LOG_INFO("Chosen Region ID: " << regionIDs[i][j]);
//        }
//    }
}

void
MeshTest::AssignChosenNodes(int number){
    indexChecks = (bool*)calloc(m_nNodes, sizeof(bool));

    for(int i=0; i<m_nNodes; i++)
        indexChecks[i] = false;
    
    for(int i=0; i<10; i++)
        indexChecks[m_targetedSMs[i]] = true;
    
//    int counter = 0;
//    int randNum;
//    while(counter < number){
//        randNum = rand()%m_nNodes;
//        if(indexChecks[randNum] == false && randNum != m_sinkID){
//            NS_LOG_INFO("Random number generated: " << randNum);
//            indexChecks[randNum] = true;
//            counter++;
//        }
//    }
    
//    indexChecks[42] = true;
//    indexChecks[0] = true;
//    indexChecks[44] = true;
//    indexChecks[36] = true;
//    indexChecks[47] = true;
//    indexChecks[32] = true;
//    indexChecks[46] = true;
//    indexChecks[27] = true;
//    indexChecks[9] = true;
//    indexChecks[26] = true;     
}

void MeshTest::ConfigureMobility (){
////////////////////////////////////MESH////////////////////////////////////////
    // Setup mobility - static grid topology
    MobilityHelper mobility;
    if (m_gridtopology) {
        mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                       "MinX", DoubleValue (0.0),
                                       "MinY", DoubleValue (0.0),
                                       "DeltaX", DoubleValue (m_step),
                                       "DeltaY", DoubleValue (m_step),
                                       "GridWidth", UintegerValue (m_xSize),
                                       "LayoutType", StringValue ("RowFirst"));
//        for (unsigned int i = 0; i < (unsigned)m_xSize; i++){
//            for (unsigned int j = 0; j < (unsigned)m_ySize; j++){
//                nodeCoords.push_back ({(j*m_step), (i*m_step)});
//            }
//        }
//
//        Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
//        for (vector< coordinates >::iterator j = nodeCoords.begin (); j != nodeCoords.end (); j++){
//            positionAlloc->Add (Vector ((*j).X, (*j).Y, m_meterHeight));
//        }
//        mobility.SetPositionAllocator (positionAlloc);
    }
    else{
        switch (m_xSize) {
            case 5:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_25[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_25[m_topoID][i]);
                break;
            case 6:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_36[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_36[m_topoID][i]);
                break;
            case 7:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_49[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_49[m_topoID][i]);
                break;
            case 8:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_64[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_64[m_topoID][i]);
                break;
            case 9:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_81[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_81[m_topoID][i]);
                break;
            case 10:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_100[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_100[m_topoID][i]);
                break;
            case 11:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_121[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_121[m_topoID][i]);
                break;
            case 12:
                for (unsigned int i = 0; i < sizeof makeArray(n_eq_144[m_topoID]); i++)
                    nodeCoords.push_back (n_eq_144[m_topoID][i]);
                break;
        }

        Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
        m_streamIndex += positionAlloc->AssignStreams (m_streamIndex);
        for (vector< coordinates >::iterator j = nodeCoords.begin (); j != nodeCoords.end (); j++){
            positionAlloc->Add (Vector ((*j).X, (*j).Y, m_meterHeight));
        }
        mobility.SetPositionAllocator (positionAlloc);
    }

    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (meshNodes);

    for (NodeContainer::Iterator j = meshNodes.Begin(); j != meshNodes.End(); ++j) {
        Ptr<Node> object = *j;
        Ptr<MobilityModel> position = object->GetObject<MobilityModel> ();
        Vector pos = position->GetPosition();

//        NS_LOG_INFO("Node " << object->GetId() << " x=" << pos.x << ", y=" << pos.y);
        
        NS_LOG_INFO("{ " << pos.x << " , " << pos.y << " },");
    }
}

void MeshTest::InstallInternetStack (){
    InternetStackHelper stack;
    stack.Install (meshNodes);

    Ipv4AddressHelper address;

    address.SetBase ("10.1.1.0", "255.255.255.0");
    meshInterfaces = address.Assign (meshDevices);
}

//Our Approach
void MeshTest::InstallApplicationMode0 (){
    // Create a map for the field values
    std::map<std::string,kodocpp::field> fieldMap;
    fieldMap["binary"] = kodocpp::field::binary;
    fieldMap["binary4"] = kodocpp::field::binary4;
    fieldMap["binary8"] = kodocpp::field::binary8;
    
//    Ptr<FWUpgradeSink> gwApp = 
//        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
//                                    fieldMap["binary8"],
//                                    (uint32_t)32,
//                                    (uint32_t)1027);
//    gwApp->SetAttribute("NBatches", UintegerValue(64));
    
    Ptr<FWUpgradeSink> gwApp = 
        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
                                     fieldMap["binary8"],
                                     (uint32_t)32,
                                     (uint32_t)491);
    gwApp->SetAttribute("NBatches", UintegerValue(134));
    
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(
        meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    gwApp->SetAttribute("NSMs", UintegerValue(m_nNodes));
    
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);

    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
//        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
//                                                   fieldMap["binary8"],
//                                                   (uint32_t)32,
//                                                   (uint32_t)1027);
//        SMApps[i]->SetAttribute("NBatches", UintegerValue(64));
        
        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
                                                   fieldMap["binary8"],
                                                   (uint32_t)32,
                                                   (uint32_t)491);
        SMApps[i]->SetAttribute("NBatches", UintegerValue(134));
        
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NSMs", UintegerValue(m_nNodes));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Unicasting with ECIES
void MeshTest::InstallApplicationMode1 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);
    
    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID || !indexChecks[i])
            continue;
        
        gwApp->SetTargetedSMAddress(Address (InetSocketAddress(meshInterfaces.GetAddress (i), 2048)));
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Flooding with MST
void MeshTest::InstallApplicationMode2 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("NChildSMs", UintegerValue(root->nChildNodes));
    gwApp->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);
    
    for(int i=0; i<(int)root->nChildNodes; i++)
        gwApp->SetTargetedSMAddress(Address (InetSocketAddress(meshInterfaces.GetAddress (root->childNodes[i]->nodeId), 2048)));
    
    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    
    NodePtr node;
    int nChildSMs;
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("NChildSMs", UintegerValue(allNodes[i]->nChildNodes));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        
        if(indexChecks[i])
            SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
                InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        meshNodes.Get(i)->AddApplication(SMApps[i]);
        
        node = allNodes[i];
        nChildSMs = node->nChildNodes;
        
        for(int j=0; j<nChildSMs; j++)
            SMApps[i]->SetTargetedSMAddress(InetSocketAddress(meshInterfaces.GetAddress(node->childNodes[j]->nodeId), 2048));
    }
}

// The whole firmware upgrade file is broadcasted by the gateway of the AMI network
void MeshTest::InstallApplicationMode3 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(
        meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    gwApp->SetAttribute("NSMs", UintegerValue(m_nNodes));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);

    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NSMs", UintegerValue(m_nNodes));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

// The FWU request is broadcasted by the GTW of the AMI network
void MeshTest::InstallApplicationMode4 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(
        meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    gwApp->SetAttribute("FirstSending", TimeValue(Seconds(m_initstart)));
    gwApp->SetAttribute("NSMs", UintegerValue(m_nNodes));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);

    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NSMs", UintegerValue(m_nNodes));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
        SMApps[i]->SetAttribute("FirstSending", TimeValue(Seconds(m_initstart)));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Unicasting the signcrypted FWUF
void MeshTest::InstallApplicationMode5 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);
    
    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID || !indexChecks[i])
            continue;
        
        gwApp->SetTargetedSMAddress(Address (InetSocketAddress(meshInterfaces.GetAddress (i), 2048)));
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Unicasting the FWU Request
void MeshTest::InstallApplicationMode6 (){
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>();
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);
    
    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID || !indexChecks[i])
            continue;
        
        gwApp->SetTargetedSMAddress(Address (InetSocketAddress(meshInterfaces.GetAddress (i), 2048)));
        
        SMApps[i] = CreateObject <FWUpgradeSource>();
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NTargetedSMs", UintegerValue(m_nChosenMeters));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Broadcasting the FWUF in multiple batches using network coding
void MeshTest::InstallApplicationMode7 (){
    // Create a map for the field values
    std::map<std::string,kodocpp::field> fieldMap;
    fieldMap["binary"] = kodocpp::field::binary;
    fieldMap["binary4"] = kodocpp::field::binary4;
    fieldMap["binary8"] = kodocpp::field::binary8;
    
//    Ptr<FWUpgradeSink> gwApp = 
//        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
//                                    fieldMap["binary8"],
//                                    (uint32_t)64,
//                                    (uint32_t)995,
//                                    (uint32_t)32);
    
//    Ptr<FWUpgradeSink> gwApp = 
//        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
//                                    fieldMap["binary8"],
//                                    (uint32_t)32,
//                                    (uint32_t)1415,
//                                    (uint32_t)47);
    
    Ptr<FWUpgradeSink> gwApp = 
        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
                                    fieldMap["binary8"],
                                    (uint32_t)32,
                                    (uint32_t)1027,
                                    (uint32_t)64);
    
//    Ptr<FWUpgradeSink> gwApp = 
//        CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
//                                     fieldMap["binary8"],
//                                     (uint32_t)32,
//                                     (uint32_t)491,
//                                     (uint32_t)134);
    
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(
        meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    gwApp->SetAttribute("NSMs", UintegerValue(m_nNodes));
    
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);

    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
//        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
//                                                   fieldMap["binary8"],
//                                                   (uint32_t)64,
//                                                   (uint32_t)995,
//                                                   (uint32_t)32);
        
//        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
//                                                   fieldMap["binary8"],
//                                                   (uint32_t)32,
//                                                   (uint32_t)1415,
//                                                   (uint32_t)47);
        
        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
                                                   fieldMap["binary8"],
                                                   (uint32_t)32,
                                                   (uint32_t)1027,
                                                   (uint32_t)64);
        
//        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
//                                                   fieldMap["binary8"],
//                                                   (uint32_t)32,
//                                                   (uint32_t)491,
//                                                   (uint32_t)134);
        
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NSMs", UintegerValue(m_nNodes));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

//Broadcasting the FWU Request in multiple batches using network coding
void MeshTest::InstallApplicationMode8 (){
    // Create a map for the field values
    std::map<std::string,kodocpp::field> fieldMap;
    fieldMap["binary"] = kodocpp::field::binary;
    fieldMap["binary4"] = kodocpp::field::binary4;
    fieldMap["binary8"] = kodocpp::field::binary8;
    
    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
                                                            fieldMap["binary8"],
                                                            (uint32_t)12,
                                                            (uint32_t)132);
    
//    Ptr<FWUpgradeSink> gwApp = CreateObject <FWUpgradeSink>(kodocpp::codec::full_vector, 
//                                                            fieldMap["binary8"],
//                                                            (uint32_t)11,
//                                                            (uint32_t)144);
    
    gwApp->SetAttribute("Local", AddressValue (Address (InetSocketAddress(
        meshInterfaces.GetAddress (m_sinkID), 4096))));
    gwApp->SetAttribute("Delay", UintegerValue(m_GWDelay));
    gwApp->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
    gwApp->SetAttribute("REQSignatureSize", UintegerValue(m_REQSignatureSize));
    gwApp->SetAttribute("Mode", UintegerValue(m_mode));
    gwApp->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));
    gwApp->SetAttribute("NSMs", UintegerValue(m_nNodes));
    
    
    gwApp->SetNode(meshNodes.Get (m_sinkID));
    gwApp->SetStartTime(Seconds (m_initstart+0.1));
    gwApp->SetStopTime(Seconds (m_totalTime+20));
    
    meshNodes.Get (m_sinkID)->AddApplication(gwApp);

    Ptr<FWUpgradeSource> SMApps[m_nNodes];
    for(int i=0; i<m_nNodes; i++){
        if(i == m_sinkID)
            continue;
        
        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
                                                   fieldMap["binary8"],
                                                   (uint32_t)12,
                                                   (uint32_t)132);
        
//        SMApps[i] = CreateObject <FWUpgradeSource>(kodocpp::codec::full_vector, 
//                                                   fieldMap["binary8"],
//                                                   (uint32_t)11,
//                                                   (uint32_t)144);
        
        SMApps[i]->SetAttribute("RemoteAddress", AddressValue (Address (
            InetSocketAddress(meshInterfaces.GetAddress (m_sinkID), 4096))));
        SMApps[i]->SetAttribute("Delay", UintegerValue (m_SMDelay));
        SMApps[i]->SetAttribute("Targeted", BooleanValue (indexChecks[i]));
        SMApps[i]->SetAttribute("SigncryptedChallengeSize", UintegerValue(m_SCH_UpSize));
        SMApps[i]->SetAttribute("Mode", UintegerValue(m_mode));
        SMApps[i]->SetAttribute("NSMs", UintegerValue(m_nNodes));
        SMApps[i]->SetAttribute("ActiveTimePeriod", DoubleValue(m_totalTime-m_initstart));

        SMApps[i]->SetNode(meshNodes.Get(i));
        SMApps[i]->SetStartTime(Seconds (0.1));
        SMApps[i]->SetStopTime(Seconds (m_totalTime+20));
        
        meshNodes.Get(i)->AddApplication(SMApps[i]);
    }
}

int MeshTest::Run (){
    CreateNodes ();
    ConfigureMobility ();
    InstallInternetStack ();
    
    if(m_mode == 0)
        InstallApplicationMode0();
    else if(m_mode == 1)
        InstallApplicationMode1();
    else if(m_mode == 2)
        InstallApplicationMode2();
    else if(m_mode == 3)
        InstallApplicationMode3();
    else if(m_mode == 4)
        InstallApplicationMode4();
    else if(m_mode == 5)
        InstallApplicationMode5();
    else if(m_mode == 6)
        InstallApplicationMode6();
    else if(m_mode == 7)
        InstallApplicationMode7();
    else if(m_mode == 8)
        InstallApplicationMode8();
    else 
        NS_LOG_ERROR("We have a problem with the mode!!!");

    m_timeStart=clock();
//    Simulator::Schedule (Seconds (m_totalTime), &MeshTest::Report, this);
    Simulator::Stop (Seconds (m_totalTime));

    Simulator::Run ();
    Simulator::Destroy ();
    m_timeEnd=clock();
    m_timeTotal=(m_timeEnd - m_timeStart)/(double) CLOCKS_PER_SEC;

    std::cout << "\n*** Simulation time: " << m_timeTotal << "s\n\n";

    m_os.close (); // close log file

    return 0;
}

void MeshTest::Report (){
    unsigned n (0);
    for (NetDeviceContainer::Iterator i = meshDevices.Begin (); i != meshDevices.End (); ++i, ++n){
        std::ostringstream os;
        os << "mp-report-" << n << "-" << m_xSize << "-" << m_velocity << ".xml";
        //      std::cerr << "Printing mesh point device #" << n << " diagnostics to " << os.str () << "\n";
        std::ofstream of;
        of.open (os.str ().c_str ());
        if (!of.is_open ()){
            std::cerr << "Error: Can't open file " << os.str () << "\n";
            return;
        }
        mesh.Report (*i, of);
        of.close ();
    }
}

Vector MeshTest::GetPosition (Ptr<Node> node){
    Ptr<MobilityModel> mobility = node->GetObject<MobilityModel> ();
    return mobility->GetPosition ();
}

int main (int argc, char *argv[]){
//    LogComponentEnable ("FWUpgradeSource", LOG_LEVEL_DEBUG);
    LogComponentEnable ("FWUpgradeSourceNW", LOG_LEVEL_ALL);
    LogComponentEnable ("TcpSocketBase", LOG_LEVEL_ALL);
//    LogComponentEnable ("FWUpgradeSink", LOG_LEVEL_DEBUG);
    LogComponentEnable ("FWUpgradeSinkNW", LOG_LEVEL_ALL);
//    LogComponentEnable ("WifiMacQueue", LOG_LEVEL_ALL);
    //  LogComponentEnable ("TcpSocketBase", LOG_LEVEL_INFO);
    //  LogComponentEnable ("UdpClient", LOG_LEVEL_ALL);
    LogComponentEnable ("SM_FW_Upgrade", LOG_LEVEL_ALL);

    MeshTest t;
    t.Configure (argc, argv);

    if(t.m_mode == 2)
        t.ReadMST();
    return t.Run ();
}
