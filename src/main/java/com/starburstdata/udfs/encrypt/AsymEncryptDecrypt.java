/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.starburstdata.udfs.encrypt;

import static io.airlift.slice.Slices.utf8Slice;
import static io.trino.spi.StandardErrorCode.GENERIC_INTERNAL_ERROR;
import static io.trino.spi.type.StandardTypes.VARCHAR;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;

import java.nio.charset.StandardCharsets;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import io.airlift.slice.Slice;
import io.trino.spi.TrinoException;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlNullable;
import io.trino.spi.function.SqlType;

public final class AsymEncryptDecrypt {

	private static final String PROJECTID = "emea-field-engineering";
	private static final String LOCATIONID = "europe-west9";
	private static final String KEYRINGID = "jerome-campo-kms";
	private static final String KEYID = "certasymmetric";
	private static final String KEYVERSIONID = "1";
	private static final AsymEncryptDecrypt INSTANCE = new AsymEncryptDecrypt();

	private static CryptoKeyVersionName keyVersionName = null;
	
	private KeyManagementServiceClient client = null;
	private PublicKey publicKey;
	private java.security.PublicKey rsaKey;
	private Cipher cipher;

	
	private AsymEncryptDecrypt() {
		try {
			init();
		} catch (InvalidKeySpecException e) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, e);
		}catch (NoSuchAlgorithmException e) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, e);
		}

	}
	// https://cloud.google.com/kms/docs/encrypt-decrypt-rsa#kms-encrypt-asymmetric-java
	private void init() throws InvalidKeySpecException, NoSuchAlgorithmException {

		try {
			client = KeyManagementServiceClient.create();
			// Build the key version name from the project, location, key ring, key,
			// and key version.
			keyVersionName = CryptoKeyVersionName.of(PROJECTID, LOCATIONID, KEYRINGID, KEYID, KEYVERSIONID);
			publicKey = client.getPublicKey(keyVersionName);
			byte[] derKey = convertPemToDer(publicKey.getPem());
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
			rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
			 cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			OAEPParameterSpec oaepParams =
				new OAEPParameterSpec(
					"SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
			cipher.init(Cipher.ENCRYPT_MODE, rsaKey, oaepParams);

		} catch (IOException exceptiom) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, exceptiom);
		}catch (InvalidKeySpecException e) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, e);
		}catch (NoSuchAlgorithmException e) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, e);
		} catch (Throwable t) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, t);
			
		}

	}

	// Converts a base64-encoded PEM certificate like the one returned from Cloud
	// KMS into a DER formatted certificate for use with the Java APIs.
	private byte[] convertPemToDer(String pem) {
		BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
		String encoded =
			bufferedReader
				.lines()
				.filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
				.collect(Collectors.joining());
		return Base64.getDecoder().decode(encoded);
	}

	@Description("UDF to encrypt with GCP Cloud KMS Asymmetric Key")
	@ScalarFunction("asymencrypt")
	@SqlType(VARCHAR)
	public static Slice asymencrypt(@SqlNullable @SqlType(VARCHAR) Slice value) {
		return utf8Slice(INSTANCE.asymencrypt_str(value.toStringUtf8()));
	}

	@Description("UDF to decrypt with GCP Cloud KMS Asymmetric Key")
	@ScalarFunction("asymdecrypt")
	@SqlType(VARCHAR)
	public static Slice asymdecrypt(@SqlNullable @SqlType(VARCHAR) Slice value) {
		return utf8Slice(INSTANCE.asymdecrypt_str(value.toStringUtf8()));
	}

	/**
	 * encrypt value and return cipherText base64 encoded
	 * 
	 * @param value text to encrypt
	 * @return base64 encrypted text
	 */
	private String asymencrypt_str(String value) {
		try {

		
			byte[] ciphertext = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
			
			return String.valueOf(ciphertext);
		} catch (Throwable t) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, t);
			
		}
	}

	/**
	 * decode base64 encoded text and return decrypted text
	 * 
	 * @param stringbase64
	 * @return
	 */
	private String asymdecrypt_str(String stringbase64) {
		try {
			
			AsymmetricDecryptResponse response =
            client.asymmetricDecrypt(keyVersionName, ByteString.copyFrom(stringbase64.getBytes(StandardCharsets.UTF_8)));
			return response.getPlaintext().toStringUtf8();
		} catch (Throwable t) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, t);
		}
	}

}
