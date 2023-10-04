using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Cryptography;
using Cryptography.Interfaces;
using System.Linq;

namespace Cryptography.KeyManagement
{
    internal class PassboltKeyManager : IKeyManager
    {
        // Configuration
        private readonly string _passboltUrl = Configuration.Config.PassboltUrl ?? throw new ArgumentNullException(nameof(Configuration.Config.PassboltUrl));
        private readonly string _userGpgPublicKey = Configuration.Config.UserGpgPublicKey ?? throw new ArgumentNullException(nameof(Configuration.Config.UserGpgPublicKey));
        private readonly string _userGpgPrivateKey = Configuration.Config.UserGpgPrivateKey ?? throw new ArgumentNullException(nameof(Configuration.Config.UserGpgPrivateKey));
        private readonly string _userGpgPassPhrase = Configuration.Config.UserGpgPassPhrase ?? throw new ArgumentNullException(nameof(Configuration.Config.UserGpgPassPhrase));

        private readonly HttpClient _httpClient;

        public PassboltKeyManager()
        {
            _httpClient = new HttpClient { BaseAddress = new Uri(_passboltUrl) };
        }

        /// <summary>
        /// Authenticates with Passbolt server using GPG key handshake.
        /// </summary>
        /// <returns>true if authentication is successful, false otherwise.</returns>
        public async Task<bool> AuthenticationWithPassbolt()
        {
            var (publicKey, fingerprint) = await VerifyServer();

            // Generate a random string to be encrypted and verified by the server
            string randomString = Convert.ToBase64String(GenerateAES256Key());
            string encryptedRandomString = Encrypt(randomString, publicKey);

            // Step 1: Send the encrypted random string to server for verification
            var gpgAuthStep1 = new { gpg_auth = new { keyid = fingerprint, server_verify_token = encryptedRandomString } };
            string jsonStep1 = JsonSerializer.Serialize(gpgAuthStep1);
            HttpResponseMessage responseStep1 = await _httpClient.PostAsync("/auth/login.json", new StringContent(jsonStep1, Encoding.UTF8, "application/json"));
            
            if (!responseStep1.IsSuccessStatusCode) return false;
            
            // Extract the encrypted token from the server's response
            string encryptedToken = responseStep1.Headers.GetValues("X-GPGAuth-User-Auth-Token").FirstOrDefault();
            if (string.IsNullOrWhiteSpace(encryptedToken)) return false;

            // Decrypt the token for the next authentication step
            string decryptedToken = Decrypt(encryptedToken, _userGpgPrivateKey);

            // Step 2: Send the decrypted token back to the server to complete authentication
            var gpgAuthStep2 = new { gpg_auth = new { user_token_result = decryptedToken } };
            string jsonStep2 = JsonSerializer.Serialize(gpgAuthStep2);
            HttpResponseMessage responseStep2 = await _httpClient.PostAsync("/auth/login.json", new StringContent(jsonStep2, Encoding.UTF8, "application/json"));

            return responseStep2.IsSuccessStatusCode;
        }

        /// <summary>
        /// Verifies the Passbolt server.
        /// </summary>
        /// <returns>A tuple containing the server's public key and its fingerprint.</returns>
        private async Task<(string publicKey, string fingerprint)> VerifyServer()
        {
            HttpResponseMessage response = await _httpClient.GetAsync("/auth/verify.json");
            string responseBody = await response.Content.ReadAsStringAsync();
            var serverInfo = JsonSerializer.Deserialize<ServerInfo>(responseBody);

            return (serverInfo.Body.KeyData, serverInfo.Body.Fingerprint);
        }

        /// <summary>
        /// Generates a 256-bit AES key.
        /// </summary>
        /// <returns>A 256-bit AES key in byte array format.</returns>
        public byte[] GenerateAES256Key()
        {
            using System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create();
            aesAlg.KeySize = 256;
            aesAlg.GenerateKey();
            return aesAlg.Key;
        }

        /// <summary>
        /// Checks if a resource with the given name exists on the Passbolt server.
        /// </summary>
        /// <param name="resourceName">Name of the resource.</param>
        /// <returns>true if resource exists, false otherwise.</returns>
        public async Task<bool> CheckResourceExists(string resourceName)
        {
            string resourceUrl = $"/resources.json?api-version=v1&filter[search]={resourceName}";
            HttpResponseMessage response = await _httpClient.GetAsync(resourceUrl);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                return !string.IsNullOrEmpty(responseBody) && IsValidResourceResponse(responseBody);
            }

            return false;
        }

        /// <summary>
        /// Fetches an encryption key for a specific resource from Passbolt.
        /// </summary>
        /// <param name="resourceName">The name of the resource to fetch the encryption key for.</param>
        /// <returns>The decrypted encryption key associated with the specified resource.</returns>
        /// <exception cref="HttpRequestException">Thrown when an error occurs while communicating with Passbolt API.</exception>
        /// <exception cref="JsonException">Thrown when the received response from Passbolt cannot be deserialized properly.</exception>
        public async Task<string> FetchKeyFromPassbolt(string resourceName)
        {
            // Construct the API endpoint to fetch resources based on the given resourceName.
            string resourceUrl = $"/resources.json?api-version=v1&filter[search]={resourceName}";
            
            HttpResponseMessage response = await _httpClient.GetAsync(resourceUrl);

            if (response.IsSuccessStatusCode)
            {
                // Parse the HTTP response to retrieve the resource details.
                string responseBody = await response.Content.ReadAsStringAsync();
                
                // Deserialize the response into a PassboltResource object.
                PassboltResource resource = JsonSerializer.Deserialize<PassboltResource>(responseBody)
                                                ?? throw new JsonException("Deserialization failed.");
                
                // Decrypt the first secret associated with the resource using the user's private key.
                return Decrypt(resource.Secrets[0].Data, _userGpgPrivateKey);
            }

            // Throw an exception if the API call was not successful.
            throw new HttpRequestException($"Error fetching the encryption key from Passbolt. Status Code: {response.StatusCode}");
        }

        /// <summary>
        /// Creates a new resource in Passbolt and associates it with an encryption key.
        /// </summary>
        /// <param name="resourceName">The name of the new resource.</param>
        /// <param name="encryptionKey">An optional byte array representing the encryption key. If not provided, a new key will be generated.</param>
        /// <returns>The Base64-encoded string representation of the associated encryption key.</returns>
        /// <exception cref="HttpRequestException">Thrown when an error occurs while communicating with Passbolt API.</exception>
        public async Task<string> CreateResourceInPassbolt(string resourceName, byte[]? encryptionKey = null)
        {
            // Generate a new AES-256 encryption key if none is provided.
            byte[] newKey = encryptionKey ?? GenerateAES256Key();

            // Convert the raw byte array encryption key to a Base64-encoded string for further processing.
            string newKeyString = Convert.ToBase64String(newKey);

            // Encrypt the Base64-encoded key using the user's GPG public key.
            string encryptedKey = Encrypt(newKeyString, _userGpgPublicKey);

            // Construct the API endpoint to create a new resource.
            string resourceUrl = $"/resources.json?api-version=v1";

            // Prepare the resource object to be sent to Passbolt.
            PassboltResource newResource = new PassboltResource
            {
                Name = resourceName,
                Secrets = new[] { new Secret { Data = encryptedKey } }
            };

            // Serialize the resource object to JSON.
            string json = JsonSerializer.Serialize(newResource);

            // Make a POST request to the Passbolt API to create the new resource.
            HttpResponseMessage response = await _httpClient.PostAsync(resourceUrl, new StringContent(json, Encoding.UTF8, "application/json"));

            if (response.IsSuccessStatusCode)
            {
                // If the resource is successfully created, return the Base64-encoded encryption key.
                return newKeyString;
            }
            else
            {
                // Throw an exception if the API call was not successful.
                throw new HttpRequestException($"Error creating the resource in Passbolt. Status Code: {response.StatusCode}");
            }
        }


        /// <summary>
        /// Validates the response from the server when checking if a resource exists.
        /// </summary>
        /// <param name="responseBody">The JSON response from the server.</param>
        /// <returns>true if valid, false otherwise.</returns>
        private bool IsValidResourceResponse(string responseBody)
        {
            try
            {
                JsonDocument doc = JsonDocument.Parse(responseBody);

                // Simplify the structure checking. The response must have body array property with at least one element containing an "id".
                return doc.RootElement.TryGetProperty("body", out JsonElement bodyProperty) && 
                       bodyProperty.ValueKind == JsonValueKind.Array && 
                       bodyProperty.GetArrayLength() > 0 &&
                       bodyProperty[0].TryGetProperty("id", out _);
            }
            catch (JsonException)
            {
                return false;
            }
        }


        /// <summary>
        /// Encrypts the given data using the provided public key.
        /// </summary>
        /// <param name="data">The plain text data to be encrypted.</param>
        /// <param name="publicKey">The user's PGP public key in ASCII-armored format.</param>
        /// <returns>Encrypted data in Base64 encoded format.</returns>
        /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
        public string Encrypt(string data, string publicKey)
        {
            try
            {
                // 1. Parse and load the provided ASCII-armored PGP public key.
                PgpPublicKey pgpPublicKey = new PgpPublicKeyRing(Encoding.UTF8.GetBytes(publicKey)).GetPublicKey();

                // 2. Initialize a literal data generator with binary format.
                PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
                MemoryStream bOut = new MemoryStream();

                // Write the data into the PGP literal data format.
                Stream lOut = lData.Open(bOut, PgpLiteralData.Binary, "_CONSOLE", data.Length, DateTime.Now);
                lOut.Write(Encoding.UTF8.GetBytes(data), 0, data.Length);
                lOut.Dispose();

                // 3. Encrypt the literal data using the public key.
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, new SecureRandom());
                cPk.AddMethod(pgpPublicKey);

                byte[] bytes = bOut.ToArray();
                MemoryStream encOut = new MemoryStream();
                Stream cOut = cPk.Open(encOut, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Dispose();

                // 4. Return the encrypted data in Base64 format.
                return Convert.ToBase64String(encOut.ToArray());
            }
            catch (Exception ex)
            {
                throw new CryptographicException("An error occurred while encrypting the data.", ex);
            }
        }

        /// <summary>
        /// Decrypts the provided encrypted data using the user's private key and passphrase.
        /// </summary>
        /// <param name="encryptedData">The encrypted data in Base64 encoded format.</param>
        /// <param name="privateKey">The user's PGP private key in ASCII-armored format.</param>
        /// <returns>Decrypted plain text data.</returns>
        /// <exception cref="CryptographicException">Thrown when decryption fails.</exception>
        public string Decrypt(string encryptedData, string privateKey)
        {
            try
            {
                // 1. Convert the Base64 encoded encrypted data back to bytes.
                byte[] encryptedDataBytes = Convert.FromBase64String(encryptedData);

                // 2. Parse the encrypted data to get the encrypted data list.
                PgpObjectFactory pgpF = new PgpObjectFactory(encryptedDataBytes);
                PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

                // 3. Extract the private key using the stored passphrase.
                PgpPrivateKey pgpPrivKey = new PgpSecretKeyRing(Encoding.ASCII.GetBytes(privateKey)).GetSecretKey().ExtractPrivateKey(_userGpgPassPhrase.ToCharArray());

                // Decrypt the actual data using the private key.
                PgpPublicKeyEncryptedData pbe = (PgpPublicKeyEncryptedData)encList[0];
                Stream clear = pbe.GetDataStream(pgpPrivKey);

                // 4. Read the decrypted literal data.
                PgpLiteralData ld = (PgpLiteralData)pgpF.NextPgpObject();
                Stream unc = ld.GetInputStream();

                // Convert the decrypted stream data back to bytes.
                MemoryStream ms = new MemoryStream();
                unc.CopyTo(ms);
                byte[] decryptedData = ms.ToArray();

                // 5. Convert the decrypted bytes back to string and return.
                return Encoding.UTF8.GetString(decryptedData);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("An error occurred while decrypting the data.", ex);
            }
        }
        
        /// <summary>
        /// Represents the server information retrieved from Passbolt.
        /// </summary>
        private class ServerInfo
        {
            /// <summary>
            /// Gets the body of the server information.
            /// </summary>
            public Body Content { get; }

            public ServerInfo(Body content)
            {
                Content = content ?? throw new ArgumentNullException(nameof(content));
            }

            /// <summary>
            /// Represents the detailed server information.
            /// </summary>
            public class Body
            {
                /// <summary>
                /// Gets the fingerprint associated with the server.
                /// </summary>
                public string Fingerprint { get; }

                /// <summary>
                /// Gets the key data from the server.
                /// </summary>
                public string KeyData { get; }

                public Body(string fingerprint, string keyData)
                {
                    Fingerprint = fingerprint ?? throw new ArgumentNullException(nameof(fingerprint));
                    KeyData = keyData ?? throw new ArgumentNullException(nameof(keyData));
                }
            }
        }

        /// <summary>
        /// Represents a resource in Passbolt.
        /// </summary>
        public class PassboltResource
        {
            /// <summary>
            /// Gets the name of the resource.
            /// </summary>
            public string Name { get; }

            /// <summary>
            /// Gets the collection of secrets associated with the resource.
            /// </summary>
            public IReadOnlyList<Secret> Secrets { get; }

            public PassboltResource(string name, IEnumerable<Secret> secrets)
            {
                Name = name ?? throw new ArgumentNullException(nameof(name));
                Secrets = (secrets ?? throw new ArgumentNullException(nameof(secrets))).ToList().AsReadOnly();
            }
        }

        /// <summary>
        /// Represents a secret data point in a Passbolt resource.
        /// </summary>
        public class Secret
        {
            /// <summary>
            /// Gets the data associated with the secret.
            /// </summary>
            public string Data { get; }

            public Secret(string data)
            {
                Data = data ?? throw new ArgumentNullException(nameof(data));
            }
        }

    }
}