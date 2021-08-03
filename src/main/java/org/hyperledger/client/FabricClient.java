/****************************************************** 
 *  Copyright 2018 IBM Corporation 
 *  Licensed under the Apache License, Version 2.0 (the "License"); 
 *  you may not use this file except in compliance with the License. 
 *  You may obtain a copy of the License at 
 *  http://www.apache.org/licenses/LICENSE-2.0 
 *  Unless required by applicable law or agreed to in writing, software 
 *  distributed under the License is distributed on an "AS IS" BASIS, 
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 *  See the License for the specific language governing permissions and 
 *  limitations under the License.
 */
package org.hyperledger.client;

import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.TransactionRequest.Type;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Wrapper class for HFClient.
 * 
 * @author Balaji Kadambi
 *
 */

public class FabricClient {

	private HFClient instance;

	/**
	 * Return an instance of HFClient.
	 * 
	 * @return
	 */
	public HFClient getInstance() {
		return instance;
	}

	/**
	 * Constructor
	 * 
	 * @param context
	 * @throws CryptoException
	 * @throws InvalidArgumentException
	 * @throws InvocationTargetException 
	 * @throws NoSuchMethodException 
	 * @throws ClassNotFoundException 
	 * @throws InstantiationException 
	 * @throws IllegalAccessException 
	 */
	public FabricClient(User context) throws CryptoException, InvalidArgumentException, IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
		CryptoSuite cryptoSuite = CryptoSuite.Factory.getCryptoSuite();
		// setup the client
		instance = HFClient.createNewInstance();
		instance.setCryptoSuite(cryptoSuite);
		instance.setUserContext(context);
	}

	/**
	 * Create a channel client.
	 * 
	 * @param name
	 * @return
	 * @throws InvalidArgumentException
	 */
	public ChannelClient createChannelClient(String name) throws InvalidArgumentException {
		Channel channel = instance.newChannel(name);
		ChannelClient client = new ChannelClient(name, channel, this);
		return client;
	}

	/**
	 * Deploy chain code.
	 * 
	 * @param chainCodeName
	 * @param chaincodePath
	 * @param codepath
	 * @param language
	 * @param version
	 * @param peers
	 * @return
	 * @throws InvalidArgumentException
	 * @throws IOException
	 * @throws ProposalException
	 */
	public String deployChainCode(String chainCodeName, String chaincodePath, String codepath,
                                  Type language, String version, Collection<Peer> peers)
			throws InvalidArgumentException, IOException, ProposalException {
		LifecycleInstallChaincodeRequest request = instance.newLifecycleInstallChaincodeRequest();
		Logger.getLogger(FabricClient.class.getName()).log(Level.INFO,
				"Deploying chaincode " + chainCodeName + " using Fabric client " + instance.getUserContext().getMspId()
						+ " " + instance.getUserContext().getName());
		LifecycleChaincodePackage lifecycleChaincodePackage = createLifecycleChaincodePackage(
				chainCodeName, // some label
				language,
				codepath,
				chaincodePath,
				 null);
		request.setLifecycleChaincodePackage(lifecycleChaincodePackage);
		request.setProposalWaitTime(120000);
		Collection<LifecycleInstallChaincodeProposalResponse> responses = instance.sendLifecycleInstallChaincodeRequest(request, peers);
		String packageID = null;
		for (LifecycleInstallChaincodeProposalResponse response : responses) {
			if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
				if (packageID == null) {
					packageID = response.getPackageId();
				}
			}
		}
		return packageID;
	}
	private LifecycleChaincodePackage createLifecycleChaincodePackage(String chaincodeLabel, Type chaincodeType, String chaincodeSourceLocation, String chaincodePath, String metadadataSource) throws IOException, InvalidArgumentException {

		Path metadataSourcePath = null;
		if (metadadataSource != null) {
			metadataSourcePath = Paths.get(metadadataSource);
		}
		LifecycleChaincodePackage lifecycleChaincodePackage = LifecycleChaincodePackage.fromSource(chaincodeLabel, Paths.get(chaincodeSourceLocation),
				chaincodeType,
				chaincodePath, metadataSourcePath);

		return lifecycleChaincodePackage;
	}
}
