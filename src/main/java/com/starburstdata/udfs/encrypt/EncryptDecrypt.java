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

import java.io.IOException;
import java.util.Base64;

import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

import io.airlift.slice.Slice;
import io.trino.spi.TrinoException;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlNullable;
import io.trino.spi.function.SqlType;

public final class EncryptDecrypt {

	private static final String PROJECTID = "your-project-id";
	private static final String LOCATIONID = "us-east1";
	private static final String KEYRINGID = "my-key-ring";
	private static final String KEYID = "my-key";
	private static final EncryptDecrypt INSTANCE = new EncryptDecrypt();

	private CryptoKeyName keyVersionName = null;
	private KeyManagementServiceClient client = null;

	private EncryptDecrypt() {
		init();

	}

	private void init() {

		try {
			client = KeyManagementServiceClient.create();
			// Build the key version name from the project, location, key ring, key,
			// and key version.
			keyVersionName = CryptoKeyName.of(PROJECTID, LOCATIONID, KEYRINGID, KEYID);
		} catch (IOException exceptiom) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, exceptiom);
		}

	}

	@Description("UDF to encrypt with Azure Keyvault Key")
	@ScalarFunction("encrypt")
	@SqlType(VARCHAR)
	public static Slice encrypt(@SqlNullable @SqlType(VARCHAR) Slice value) {
		return utf8Slice(INSTANCE.encrypt_str(value.toStringUtf8()));
	}

	@Description("UDF to decrypt with Azure Keyvault Key")
	@ScalarFunction("decrypt")
	@SqlType(VARCHAR)
	public static Slice decrypt(@SqlNullable @SqlType(VARCHAR) Slice value) {
		return utf8Slice(INSTANCE.decrypt_str(value.toStringUtf8()));
	}

	/**
	 * encrypt value and return cipherText base64 encoded
	 * 
	 * @param value text to encrypt
	 * @return base64 encrypted text
	 */
	private String encrypt_str(String value) {
		try {

			EncryptResponse response = client.encrypt(keyVersionName, ByteString.copyFromUtf8(value));
			
			return String.valueOf(Base64.getEncoder().encode(response.getCiphertext().toByteArray()));
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
	private String decrypt_str(String stringbase64) {
		try {
			
			byte[] content=Base64.getDecoder().decode(stringbase64);
			DecryptResponse response = client.decrypt(keyVersionName, ByteString.copyFrom(content));
			return response.getPlaintext().toStringUtf8();
		} catch (Throwable t) {
			throw new TrinoException(GENERIC_INTERNAL_ERROR, t);
		}
	}

}
