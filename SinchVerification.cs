using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ApplicationRequestSigningSinchApi
{
    public static class SinchVerification
    {
        [FunctionName("SinchVerification")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("SinchVerification HTTP trigger function processed a request.");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JObject.Parse(requestBody);

            string phoneNumber = data.phoneNumber;
            string applicationKey = "f299206d-02b6-4f18-920c-3ff960987e32";//Environment.GetEnvironmentVariable("SinchAppKey");
            string applicationSecret = "MgaXzgQrLEG0yDKMmekNFg==";//Environment.GetEnvironmentVariable("SinchAppSecret");
            string sinchVerificationUrl = "https://verification.api.sinch.com/verification/v1/verifications";//"https://verificationapi-v1.sinch.com/verification/v1/verifications";

            string verificationRequest = $"{{\"identity\":{{\"type\":\"number\",\"endpoint\":\"{phoneNumber}\"}},\"method\":\"sms\"}}";
            log.LogInformation($"VerificationRequest:{verificationRequest}");
            byte[] encodedVerificationRequest = Encoding.UTF8.GetBytes(verificationRequest);
            log.LogInformation($"EncodetoDecode:" + Encoding.UTF8.GetString(encodedVerificationRequest));
            string contentMD5 = "";
            if (encodedVerificationRequest.Length > 0)
            {
                using MD5 md5 = MD5.Create();
                byte[] hash = md5.ComputeHash(encodedVerificationRequest);
                contentMD5 = Convert.ToBase64String(hash);
            }

            string httpVerb = "POST";
            string requestContentType = "application/json";
            string timeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
            log.LogInformation($"timestamp:{timeNow}");
            string requestTimeStamp = "x-timestamp:" + timeNow;
            string requestUriPath = "/verification/v1/verifications";

            string stringToSign = string.Join("\n", httpVerb, contentMD5, requestContentType, requestTimeStamp, requestUriPath);
            log.LogInformation($"String to Sign:" + stringToSign);
            using HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(applicationSecret));
            byte[] hmacSha256 = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));

            string authorizationSiganture = Convert.ToBase64String(hmacSha256);
            string authorizationHeader = $"Application {applicationKey}:{authorizationSiganture}";

            using HttpClient httpClient = new HttpClient();

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, sinchVerificationUrl);
            // request.Headers.Add("Content-Type", "application/json");
            request.Headers.Add("x-timestamp", timeNow);
            request.Headers.Add("Authorization", authorizationHeader);
            request.Content = new StringContent(verificationRequest, Encoding.UTF8, requestContentType);

            HttpResponseMessage response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                return new OkObjectResult(responseBody);
            }
            else
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                dynamic responseData = JObject.Parse(responseBody);
                log.LogError($"Response Content:{responseData} ");
                string errorMessage = $"Error: {response.StatusCode}";
                return new BadRequestObjectResult(errorMessage);
            }

            var responseBodyNew = new JObject
            {
                { "phoneNumber", phoneNumber }
            };

            return new OkObjectResult(responseBodyNew);
        }
    }
}
