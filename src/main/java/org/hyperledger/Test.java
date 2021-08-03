package org.hyperledger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.client.CAClient;
import org.hyperledger.client.FabricClient;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.user.UserContext;
import org.hyperledger.util.Util;
import org.whu.gmssl.jsse.provider.GMJsseProvider;

import java.security.Security;
import java.util.Collection;
import java.util.Properties;

public class Test {
    static {
        Security.insertProviderAt(new GMJsseProvider(),1);
        Security.insertProviderAt(new BouncyCastleProvider(),2);
    }
    public static void main(String[] args) throws Exception {
        Util.cleanUp();
//        UserContext org1Admin = new UserContext();
//        Enrollment enrollOrg1Admin = Util.getEnrollment("C:\\Users\\MSI\\Desktop\\fabric-sdk-gm\\fabric-sdk-java-2.2.0-gm-main\\organizations\\peerOrganizations\\org1.xxzx.com\\users\\Admin@org1.xxzx.com\\msp\\keystore\\11bde132ae90cf0fddbc09356ad5bd7d4eafd0a9ce7b0a7f30ab739c9a764bb0_sk", null,
//                "C:\\Users\\MSI\\Desktop\\fabric-sdk-gm\\fabric-sdk-java-2.2.0-gm-main\\organizations\\peerOrganizations\\org1.xxzx.com\\users\\Admin@org1.xxzx.com\\msp\\keystore\\11bde132ae90cf0fddbc09356ad5bd7d4eafd0a9ce7b0a7f30ab739c9a764bb0_sk", null);
//        org1Admin.setEnrollment(enrollOrg1Admin);
//        org1Admin.setMspId("Org1MSP");
//        org1Admin.setName("admin");
//        org1Admin.setAffiliation("org1");
        UserContext adminUser = new UserContext();
        adminUser.setName("admin");
        adminUser.setAffiliation("org1");
        adminUser.setMspId("Org1MSP");
        //adminUser.setEnrollment(enrollOrg1Admin);
        Properties properties = new Properties();
        CAClient caclient=new  CAClient("http://ca.org1.xxzx.com:7054", properties);
        caclient.setAdminUserContext(adminUser);
        adminUser =  caclient.enrollAdminUser("admin", "adminpw");
        FabricClient fabClient = new FabricClient(adminUser);
        HFClient client = fabClient.getInstance();
        Properties orderer1Prop = new Properties();
//        orderer1Prop.setProperty("pemFile", "C:\\Users\\MSI\\Desktop\\gm-fabric\\fabric-jdk-java\\java\\src\\main\\resources\\order.crt");
//        orderer1Prop.setProperty("sslProvider", "openSSL");
//        orderer1Prop.setProperty("negotiationType", "TLS");
//        orderer1Prop.setProperty("hostnameOverride", "orderer.xxzx.com");
//        orderer1Prop.setProperty("trustServerCertificate", "true");
//        orderer1Prop.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
        Orderer orderer = client.newOrderer("orderer.xxzx.com", "grpc://orderer.xxzx.com:7050", orderer1Prop);

        Properties peer1Prop = new Properties();
//        peer1Prop.setProperty("pemFile", "C:\\Users\\MSI\\Desktop\\gm-fabric\\fabric-jdk-java\\java\\src\\main\\resources\\ca1.crt");
//        peer1Prop.setProperty("sslProvider", "openSSL");
//        peer1Prop.setProperty("negotiationType", "TLS");
//        peer1Prop.setProperty("hostnameOverride", "peer0.org1.xxzx.com");
//        peer1Prop.setProperty("trustServerCertificate", "true");
//        peer1Prop.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
        Peer peer = client.newPeer("peer0.org1.xxzx.com", "grpc://peer0.org1.xxzx.com:8051", peer1Prop);
        Channel mychannel = client.newChannel("mychannel");
        mychannel.addOrderer(orderer);
        mychannel.addPeer(peer);
        Channel channel = mychannel.initialize();
        QueryByChaincodeRequest query = QueryByChaincodeRequest.newInstance(adminUser);
        QueryByChaincodeRequest request = fabClient.getInstance().newQueryProposalRequest();
        ChaincodeID ccid = ChaincodeID.newBuilder().setName("abs").build();
        request.setChaincodeID(ccid);
        request.setFcn("get");
        request.setArgs("user","1");
        Collection<ProposalResponse> response = channel.queryByChaincode(request);
        System.out.println(response);
    }
}
