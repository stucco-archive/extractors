import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class SituCyboxExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one record - no bytes or counts") {
    val node = XmlParser("""
        <cybox:Observables xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:NetFlowObj="http://cybox.mitre.org/objects#NetworkFlowObject-2" xmlns:SocketAddressObj="http://cybox.mitre.org/objects#SocketAddressObject-1" xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2" xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2">
            <cybox:Observable id="6e104843-1c1f-5c76-87c0-4647915aa251">
                <cybox:Description>SITU Network Flow Observable</cybox:Description>
                <cybox:Object id="6e104843-1c1f-5c76-87c0-4647915aa251">
                    <cybox:Properties xsi:type="NetFlowObj:NetworkFlowObjectType">
                        <NetFlowObj:Network_Flow_Label>
                            <NetFlowObj:Source_Socket_Address>
                                <SocketAddressObj:IP_Address>
                                    <AddressObj:Address_Value>128.219.49.14</AddressObj:Address_Value>
                                </SocketAddressObj:IP_Address>
                                <SocketAddressObj:Port>
                                    <PortObj:Port_Value>48980</PortObj:Port_Value>
                                </SocketAddressObj:Port>
                            </NetFlowObj:Source_Socket_Address>
                            <NetFlowObj:Destination_Socket_Address>
                                <SocketAddressObj:IP_Address>
                                    <AddressObj:Address_Value>52.5.45.166</AddressObj:Address_Value>
                                </SocketAddressObj:IP_Address>
                                <SocketAddressObj:Port>
                                    <PortObj:Port_Value>80</PortObj:Port_Value>
                                </SocketAddressObj:Port>
                            </NetFlowObj:Destination_Socket_Address>
                            <NetFlowObj:IP_Protocol>tcp</NetFlowObj:IP_Protocol>
                        </NetFlowObj:Network_Flow_Label>
                        <NetFlowObj:SITU_Score>0</NetFlowObj:SITU_Score>
                    </cybox:Properties>
                </cybox:Object>
            </cybox:Observable>
        </cybox:Observables>
      """)
    //println(node)
    val entries = SituCyboxExtractor(node)
    //println(entries)

    assert(entries ~> "vertices" ~> 0 ~> "_id" === Some(S("128.219.49.14:48980::52.5.45.166:80")))
    assert(entries ~> "vertices" ~> 0 ~> "name" === Some(S("128.219.49.14:48980::52.5.45.166:80")))
    assert(entries ~> "vertices" ~> 0 ~> "description" === Some(S("128.219.49.14, port 48980 to 52.5.45.166, port 80")))
    assert(entries ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 0 ~> "vertexType" === Some(S("flow")))
    assert(entries ~> "vertices" ~> 0 ~> "source" === Some(S("situ")))
    assert(entries ~> "vertices" ~> 0 ~> "proto" === Some(S("tcp")))
    assert(entries ~> "vertices" ~> 0 ~> "situScore" === Some(N(0)))
    //assert(entries ~> "vertices" ~> 0 ~> "appBytes" === Some(S("585")))
    //assert(entries ~> "vertices" ~> 0 ~> "startTime" === Some(N(1373553586136L)))
    //assert(entries ~> "vertices" ~> 0 ~> "dir" === Some(S("   ->")))
    //assert(entries ~> "vertices" ~> 0 ~> "flags" === Some(S(" e s      ")))
    //assert(entries ~> "vertices" ~> 0 ~> "state" === Some(S("REQ")))

    assert(entries ~> "vertices" ~> 1 ~> "_id" === Some(S("128.219.49.14:48980")))
    assert(entries ~> "vertices" ~> 1 ~> "name" === Some(S("128.219.49.14:48980")))
    assert(entries ~> "vertices" ~> 1 ~> "description" === Some(S("128.219.49.14, port 48980")))
    assert(entries ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 1 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 1 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 2 ~> "_id" === Some(S("52.5.45.166:80")))
    assert(entries ~> "vertices" ~> 2 ~> "name" === Some(S("52.5.45.166:80")))
    assert(entries ~> "vertices" ~> 2 ~> "description" === Some(S("52.5.45.166, port 80")))
    assert(entries ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 2 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 3 ~> "_id" === Some(S("128.219.49.14")))
    assert(entries ~> "vertices" ~> 3 ~> "name" === Some(S("128.219.49.14")))
    assert(entries ~> "vertices" ~> 3 ~> "description" === Some(S("128.219.49.14")))
    assert(entries ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 3 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 3 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 4 ~> "_id" === Some(S("52.5.45.166")))
    assert(entries ~> "vertices" ~> 4 ~> "name" === Some(S("52.5.45.166")))
    assert(entries ~> "vertices" ~> 4 ~> "description" === Some(S("52.5.45.166")))
    assert(entries ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 4 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 5 ~> "_id" === Some(S("48980")))
    assert(entries ~> "vertices" ~> 5 ~> "name" === Some(S("48980")))
    assert(entries ~> "vertices" ~> 5 ~> "description" === Some(S("48980")))
    assert(entries ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 5 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 5 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 6 ~> "_id" === Some(S("80")))
    assert(entries ~> "vertices" ~> 6 ~> "name" === Some(S("80")))
    assert(entries ~> "vertices" ~> 6 ~> "description" === Some(S("80")))
    assert(entries ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 6 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 7 === None)

    assert(entries ~> "edges" ~> 0 ~> "_id" === Some(S("128.219.49.14:48980::52.5.45.166:80_srcAddress_128.219.49.14:48980")))
    assert(entries ~> "edges" ~> 0 ~> "description" === Some(S("128.219.49.14, port 48980 to 52.5.45.166, port 80 has source address 128.219.49.14, port 48980")))
    assert(entries ~> "edges" ~> 0 ~> "_outV" === Some(S("128.219.49.14:48980::52.5.45.166:80")))
    assert(entries ~> "edges" ~> 0 ~> "_inV" === Some(S("128.219.49.14:48980")))
    assert(entries ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 0 ~> "_label" === Some(S("srcAddress")))
    assert(entries ~> "edges" ~> 0 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 0 ~> "outVType" === Some(S("flow")))
    assert(entries ~> "edges" ~> 0 ~> "inVType" === Some(S("address")))
    
    assert(entries ~> "edges" ~> 1 ~> "_id" === Some(S("128.219.49.14:48980::52.5.45.166:80_dstAddress_52.5.45.166:80")))
    assert(entries ~> "edges" ~> 1 ~> "description" === Some(S("128.219.49.14, port 48980 to 52.5.45.166, port 80 has destination address 52.5.45.166, port 80")))
    assert(entries ~> "edges" ~> 1 ~> "_outV" === Some(S("128.219.49.14:48980::52.5.45.166:80")))
    assert(entries ~> "edges" ~> 1 ~> "_inV" === Some(S("52.5.45.166:80")))
    assert(entries ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 1 ~> "_label" === Some(S("dstAddress")))
    assert(entries ~> "edges" ~> 1 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 1 ~> "outVType" === Some(S("flow")))
    assert(entries ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))

    assert(entries ~> "edges" ~> 2 ~> "_id" === Some(S("128.219.49.14:48980_hasIP_128.219.49.14")))
    assert(entries ~> "edges" ~> 2 ~> "description" === Some(S("128.219.49.14, port 48980 has IP 128.219.49.14")))
    assert(entries ~> "edges" ~> 2 ~> "_outV" === Some(S("128.219.49.14:48980")))
    assert(entries ~> "edges" ~> 2 ~> "_inV" === Some(S("128.219.49.14")))
    assert(entries ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(entries ~> "edges" ~> 2 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 2 ~> "inVType" === Some(S("IP")))

    assert(entries ~> "edges" ~> 3 ~> "_id" === Some(S("52.5.45.166:80_hasIP_52.5.45.166")))
    assert(entries ~> "edges" ~> 3 ~> "description" === Some(S("52.5.45.166, port 80 has IP 52.5.45.166")))
    assert(entries ~> "edges" ~> 3 ~> "_outV" === Some(S("52.5.45.166:80")))
    assert(entries ~> "edges" ~> 3 ~> "_inV" === Some(S("52.5.45.166")))
    assert(entries ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    assert(entries ~> "edges" ~> 3 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))
    
    assert(entries ~> "edges" ~> 4 ~> "_id" === Some(S("128.219.49.14:48980_hasPort_48980")))
    assert(entries ~> "edges" ~> 4 ~> "description" === Some(S("128.219.49.14, port 48980 has port 48980")))
    assert(entries ~> "edges" ~> 4 ~> "_outV" === Some(S("128.219.49.14:48980")))
    assert(entries ~> "edges" ~> 4 ~> "_inV" === Some(S("48980")))
    assert(entries ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 4 ~> "_label" === Some(S("hasPort")))
    assert(entries ~> "edges" ~> 4 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 4 ~> "inVType" === Some(S("port")))

    assert(entries ~> "edges" ~> 5 ~> "_id" === Some(S("52.5.45.166:80_hasPort_80")))
    assert(entries ~> "edges" ~> 5 ~> "description" === Some(S("52.5.45.166, port 80 has port 80")))
    assert(entries ~> "edges" ~> 5 ~> "_outV" === Some(S("52.5.45.166:80")))
    assert(entries ~> "edges" ~> 5 ~> "_inV" === Some(S("80")))
    assert(entries ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(entries ~> "edges" ~> 5 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(entries ~> "edges" ~> 6 === None)

  }

  test("parse one complete record") {
    val node = XmlParser("""
        <cybox:Observables xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:NetFlowObj="http://cybox.mitre.org/objects#NetworkFlowObject-2" xmlns:SocketAddressObj="http://cybox.mitre.org/objects#SocketAddressObject-1" xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2" xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2">
            <cybox:Observable id="de305d54-75b4-431b-adb2-eb6b9e546013">
                <cybox:Description>SITU Network Flow Observable</cybox:Description>
                <cybox:Object id="de305d54-75b4-431b-adb2-eb6b9e546013">
                    <cybox:Properties xsi:type="NetFlowObj:NetworkFlowObjectType">
                        <NetFlowObj:Network_Flow_Label>
                            <NetFlowObj:Source_Socket_Address>
                                <SocketAddressObj:IP_Address>
                                    <AddressObj:Address_Value>1.2.3.4</AddressObj:Address_Value>
                                </SocketAddressObj:IP_Address>
                                <SocketAddressObj:Port>
                                    <PortObj:Port_Value>1000</PortObj:Port_Value>
                                </SocketAddressObj:Port>
                            </NetFlowObj:Source_Socket_Address>
                            <NetFlowObj:Destination_Socket_Address>
                                <SocketAddressObj:IP_Address>
                                    <AddressObj:Address_Value>5.6.7.8</AddressObj:Address_Value>
                                </SocketAddressObj:IP_Address>
                                <SocketAddressObj:Port>
                                    <PortObj:Port_Value>1001</PortObj:Port_Value>
                                </SocketAddressObj:Port>
                            </NetFlowObj:Destination_Socket_Address>
                            <NetFlowObj:IP_Protocol>proto</NetFlowObj:IP_Protocol>
                        </NetFlowObj:Network_Flow_Label>
                        <NetFlowObj:Unidirectional_Flow_Record>
                            <NetFlowObj:Cooperative_Protection_Program_Record>
                                <Cooperative_Protection_Program:Site>site</Cooperative_Protection_Program:Site>
                                <Cooperative_Protection_Program:Time>2006-01-02T15:04:05.999999999Z07:00</Cooperative_Protection_Program:Time>
                                <Cooperative_Protection_Program:Duration>100</Cooperative_Protection_Program:Duration>
                                <Cooperative_Protection_Program:SrcAppBytes>101</Cooperative_Protection_Program:SrcAppBytes>
                                <Cooperative_Protection_Program:DstAppBytes>102</Cooperative_Protection_Program:DstAppBytes>
                                <Cooperative_Protection_Program:AppBytes>103</Cooperative_Protection_Program:AppBytes>
                                <Cooperative_Protection_Program:SrcBytes>104</Cooperative_Protection_Program:SrcBytes>
                                <Cooperative_Protection_Program:DstBytes>105</Cooperative_Protection_Program:DstBytes>
                                <Cooperative_Protection_Program:Bytes>106</Cooperative_Protection_Program:Bytes>
                                <Cooperative_Protection_Program:SrcPackets>107</Cooperative_Protection_Program:SrcPackets>
                                <Cooperative_Protection_Program:DstPackets>108</Cooperative_Protection_Program:DstPackets>
                                <Cooperative_Protection_Program:Packets>109</Cooperative_Protection_Program:Packets>
                                <Cooperative_Protection_Program:Flags>+a +b -c +d -e</Cooperative_Protection_Program:Flags>
                            </NetFlowObj:Cooperative_Protection_Program_Record>
                        </NetFlowObj:Unidirectional_Flow_Record>
                        <NetFlowObj:SITU_Score>9.876543</NetFlowObj:SITU_Score>
                    </cybox:Properties>
                </cybox:Object>
            </cybox:Observable>
        </cybox:Observables>
      """)
    //println(node)
    val entries = SituCyboxExtractor(node)
    //println(entries)

    assert(entries ~> "vertices" ~> 0 ~> "_id" === Some(S("1.2.3.4:1000::5.6.7.8:1001")))
    assert(entries ~> "vertices" ~> 0 ~> "name" === Some(S("1.2.3.4:1000::5.6.7.8:1001")))
    assert(entries ~> "vertices" ~> 0 ~> "description" === Some(S("1.2.3.4, port 1000 to 5.6.7.8, port 1001")))
    assert(entries ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 0 ~> "vertexType" === Some(S("flow")))
    assert(entries ~> "vertices" ~> 0 ~> "source" === Some(S("situ")))
    assert(entries ~> "vertices" ~> 0 ~> "proto" === Some(S("proto")))
    assert(entries ~> "vertices" ~> 0 ~> "situScore" === Some(N(9.876543)))

    assert(entries ~> "vertices" ~> 0 ~> "site" === Some(S("site")))
    assert(entries ~> "vertices" ~> 0 ~> "duration" === Some(N(100)))
    assert(entries ~> "vertices" ~> 0 ~> "srcAppBytes" === Some(N(101)))
    assert(entries ~> "vertices" ~> 0 ~> "dstAppBytes" === Some(N(102)))
    assert(entries ~> "vertices" ~> 0 ~> "appBytes" === Some(N(103)))
    assert(entries ~> "vertices" ~> 0 ~> "srcBytes" === Some(N(104)))
    assert(entries ~> "vertices" ~> 0 ~> "dstBytes" === Some(N(105)))
    assert(entries ~> "vertices" ~> 0 ~> "bytes" === Some(N(106)))
    assert(entries ~> "vertices" ~> 0 ~> "srcPackets" === Some(N(107)))
    assert(entries ~> "vertices" ~> 0 ~> "dstPackets" === Some(N(108)))
    assert(entries ~> "vertices" ~> 0 ~> "packets" === Some(N(109)))
    
    //assert(entries ~> "vertices" ~> 0 ~> "startTime" === Some(N(1136189046000L)))
    //assert(entries ~> "vertices" ~> 0 ~> "dir" === Some(S("   ->")))
    assert(entries ~> "vertices" ~> 0 ~> "flags" === Some(S("+a +b -c +d -e")))
    //assert(entries ~> "vertices" ~> 0 ~> "state" === Some(S("REQ")))

    assert(entries ~> "vertices" ~> 1 ~> "_id" === Some(S("1.2.3.4:1000")))
    assert(entries ~> "vertices" ~> 1 ~> "name" === Some(S("1.2.3.4:1000")))
    assert(entries ~> "vertices" ~> 1 ~> "description" === Some(S("1.2.3.4, port 1000")))
    assert(entries ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 1 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 1 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 2 ~> "_id" === Some(S("5.6.7.8:1001")))
    assert(entries ~> "vertices" ~> 2 ~> "name" === Some(S("5.6.7.8:1001")))
    assert(entries ~> "vertices" ~> 2 ~> "description" === Some(S("5.6.7.8, port 1001")))
    assert(entries ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 2 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 3 ~> "_id" === Some(S("1.2.3.4")))
    assert(entries ~> "vertices" ~> 3 ~> "name" === Some(S("1.2.3.4")))
    assert(entries ~> "vertices" ~> 3 ~> "description" === Some(S("1.2.3.4")))
    assert(entries ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 3 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 3 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 4 ~> "_id" === Some(S("5.6.7.8")))
    assert(entries ~> "vertices" ~> 4 ~> "name" === Some(S("5.6.7.8")))
    assert(entries ~> "vertices" ~> 4 ~> "description" === Some(S("5.6.7.8")))
    assert(entries ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 4 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 5 ~> "_id" === Some(S("1000")))
    assert(entries ~> "vertices" ~> 5 ~> "name" === Some(S("1000")))
    assert(entries ~> "vertices" ~> 5 ~> "description" === Some(S("1000")))
    assert(entries ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 5 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 5 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 6 ~> "_id" === Some(S("1001")))
    assert(entries ~> "vertices" ~> 6 ~> "name" === Some(S("1001")))
    assert(entries ~> "vertices" ~> 6 ~> "description" === Some(S("1001")))
    assert(entries ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 6 ~> "source" === Some(S("situ")))

    assert(entries ~> "vertices" ~> 7 === None)

    assert(entries ~> "edges" ~> 0 ~> "_id" === Some(S("1.2.3.4:1000::5.6.7.8:1001_srcAddress_1.2.3.4:1000")))
    assert(entries ~> "edges" ~> 0 ~> "description" === Some(S("1.2.3.4, port 1000 to 5.6.7.8, port 1001 has source address 1.2.3.4, port 1000")))
    assert(entries ~> "edges" ~> 0 ~> "_outV" === Some(S("1.2.3.4:1000::5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 0 ~> "_inV" === Some(S("1.2.3.4:1000")))
    assert(entries ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 0 ~> "_label" === Some(S("srcAddress")))
    assert(entries ~> "edges" ~> 0 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 0 ~> "outVType" === Some(S("flow")))
    assert(entries ~> "edges" ~> 0 ~> "inVType" === Some(S("address")))
    
    assert(entries ~> "edges" ~> 1 ~> "_id" === Some(S("1.2.3.4:1000::5.6.7.8:1001_dstAddress_5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 1 ~> "description" === Some(S("1.2.3.4, port 1000 to 5.6.7.8, port 1001 has destination address 5.6.7.8, port 1001")))
    assert(entries ~> "edges" ~> 1 ~> "_outV" === Some(S("1.2.3.4:1000::5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 1 ~> "_inV" === Some(S("5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 1 ~> "_label" === Some(S("dstAddress")))
    assert(entries ~> "edges" ~> 1 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 1 ~> "outVType" === Some(S("flow")))
    assert(entries ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))

    assert(entries ~> "edges" ~> 2 ~> "_id" === Some(S("1.2.3.4:1000_hasIP_1.2.3.4")))
    assert(entries ~> "edges" ~> 2 ~> "description" === Some(S("1.2.3.4, port 1000 has IP 1.2.3.4")))
    assert(entries ~> "edges" ~> 2 ~> "_outV" === Some(S("1.2.3.4:1000")))
    assert(entries ~> "edges" ~> 2 ~> "_inV" === Some(S("1.2.3.4")))
    assert(entries ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(entries ~> "edges" ~> 2 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 2 ~> "inVType" === Some(S("IP")))

    assert(entries ~> "edges" ~> 3 ~> "_id" === Some(S("5.6.7.8:1001_hasIP_5.6.7.8")))
    assert(entries ~> "edges" ~> 3 ~> "description" === Some(S("5.6.7.8, port 1001 has IP 5.6.7.8")))
    assert(entries ~> "edges" ~> 3 ~> "_outV" === Some(S("5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 3 ~> "_inV" === Some(S("5.6.7.8")))
    assert(entries ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    assert(entries ~> "edges" ~> 3 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))
    
    assert(entries ~> "edges" ~> 4 ~> "_id" === Some(S("1.2.3.4:1000_hasPort_1000")))
    assert(entries ~> "edges" ~> 4 ~> "description" === Some(S("1.2.3.4, port 1000 has port 1000")))
    assert(entries ~> "edges" ~> 4 ~> "_outV" === Some(S("1.2.3.4:1000")))
    assert(entries ~> "edges" ~> 4 ~> "_inV" === Some(S("1000")))
    assert(entries ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 4 ~> "_label" === Some(S("hasPort")))
    assert(entries ~> "edges" ~> 4 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 4 ~> "inVType" === Some(S("port")))

    assert(entries ~> "edges" ~> 5 ~> "_id" === Some(S("5.6.7.8:1001_hasPort_1001")))
    assert(entries ~> "edges" ~> 5 ~> "description" === Some(S("5.6.7.8, port 1001 has port 1001")))
    assert(entries ~> "edges" ~> 5 ~> "_outV" === Some(S("5.6.7.8:1001")))
    assert(entries ~> "edges" ~> 5 ~> "_inV" === Some(S("1001")))
    assert(entries ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(entries ~> "edges" ~> 5 ~> "source" === Some(S("situ")))
    assert(entries ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(entries ~> "edges" ~> 6 === None)

  }
}