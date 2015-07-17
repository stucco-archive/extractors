package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * CleanMX Virus data extractor.
 *
 * @author Mike Iannacone
 */
object SituCyboxExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //TODO: it would be useful to also check non-strings here.
  //TODO: also this is c&p from hone extractor, no good...
  def notEmpty(node: Option[ValueNode]): Boolean = {
    node != None && node != Some(S(""))
  }

  def getTime(node: Option[ValueNode]): Option[ValueNode] = {
    if(notEmpty(node)){
      val dateString = node.asString
      val format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSXXX")
      if(dateString != ""){
        return format.parse(dateString).getTime()
      }
    }
    return None
  }

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "cybox:Observables" ~> "cybox:Observable" ~> "cybox:Object" %%-> { item =>
      *(
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "name" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " to " +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "vertex",
            "vertexType" -> "flow",
            "source" -> "situ",
            "proto" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:IP_Protocol",
            "situScore" -> item ~> "cybox:Properties" ~> "NetFlowObj:SITU_Score",
            "startTime" -> getTime(item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Time"),
            //"startTime" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Time", //TODO convert
            "site" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Site",
            "duration" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Duration",
            "srcAppBytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:SrcAppBytes",
            "dstAppBytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:DstAppBytes",
            "appBytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:AppBytes",
            "srcBytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:SrcBytes",
            "dstBytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:DstBytes",
            "bytes" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Bytes",
            "srcPackets" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:SrcPackets",
            "dstPackets" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:DstPackets",
            "packets" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Packets",
            "flags" -> item ~> "cybox:Properties" ~> "NetFlowObj:Unidirectional_Flow_Record" ~> "NetFlowObj:Cooperative_Protection_Program_Record" ~> "Cooperative_Protection_Program:Flags"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "name" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "situ"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "name" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "situ"
          )
        },
        {
          ^(
            "_id" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "name" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "description" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "situ"
          )
        },
        {
          ^(
            "_id" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "name" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "description" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "situ"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "name" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "situ"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "name" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "situ"
          )
        }
      )
    }).encapsulate.autoFlatten,
    "edges" -> (node ~> "cybox:Observables" ~> "cybox:Observable" ~> "cybox:Object" %%-> { item =>
      *(
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_srcAddress_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " to " +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has source address " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "edge",
            "inVType" -> "address",
            "outVType" -> "flow",
            "source" -> "situ",
            "_inV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "srcAddress"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_dstAddress_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " to " +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has destination address " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "edge",
            "inVType" -> "address",
            "outVType" -> "flow",
            "source" -> "situ",
            "_inV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "::" +
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "dstAddress"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_hasIP_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has IP " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString
                    },
            "_type" -> "edge",
            "inVType" -> "IP",
            "outVType" -> "address",
            "source" -> "situ",
            "_inV" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "hasIP"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_hasIP_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has IP " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString
                    },
            "_type" -> "edge",
            "inVType" -> "IP",
            "outVType" -> "address",
            "source" -> "situ",
            "_inV" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "hasIP"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_hasPort_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "edge",
            "inVType" -> "port",
            "outVType" -> "address",
            "source" -> "situ",
            "_inV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "hasPort"
          )
        },
        {
          ^(
            "_id" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + "_hasPort_" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "description" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ", port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber + " has port " + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_type" -> "edge",
            "inVType" -> "port",
            "outVType" -> "address",
            "source" -> "situ",
            "_inV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber.toString
                    },
            "_outV" -> Safely {
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value").asString + ":" + 
                      (item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:Port" ~> "PortObj:Port_Value").asNumber
                    },
            "_label" -> "hasPort"
          )
        }
      )
    }).autoFlatten
  )
}
