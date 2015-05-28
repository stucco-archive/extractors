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
            "source" -> "SITU",
            "proto" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:IP_Protocol",
            "SITUScore" -> item ~> "cybox:Properties" ~> "NetFlowObj:SITU_Score"
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
            "source" -> "SITU"
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
            "source" -> "SITU"
          )
        },
        {
          ^(
            "_id" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "name" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "description" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Source_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "SITU"
          )
        },
        {
          ^(
            "_id" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "name" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "description" -> item ~> "cybox:Properties" ~> "NetFlowObj:Network_Flow_Label" ~> "NetFlowObj:Destination_Socket_Address" ~> "SocketAddressObj:IP_Address" ~> "AddressObj:Address_Value",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "SITU"
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
            "source" -> "SITU"
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
            "source" -> "SITU"
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
            "source" -> "SITU",
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
            "source" -> "SITU",
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
            "source" -> "SITU",
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
            "source" -> "SITU",
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
            "source" -> "SITU",
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
            "source" -> "SITU",
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
