import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Random;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class MobicardDetokenization {
    
    private final String mobicardVersion = "2.0";
    private final String mobicardMode = "LIVE";
    private final String mobicardMerchantId;
    private final String mobicardApiKey;
    private final String mobicardSecretKey;
    private final String mobicardServiceId = "20000";
    private final String mobicardServiceType = "DETOKENIZATION";
    
    private final String mobicardTokenId;
    private final String mobicardTxnReference;
    
    private final Gson gson = new Gson();
    
    public MobicardDetokenization(String merchantId, String apiKey, String secretKey) {
        this.mobicardMerchantId = merchantId;
        this.mobicardApiKey = apiKey;
        this.mobicardSecretKey = secretKey;
        
        Random random = new Random();
        this.mobicardTokenId = String.valueOf(random.nextInt(900000000) + 1000000);
        this.mobicardTxnReference = String.valueOf(random.nextInt(900000000) + 1000000);
    }
    
    public String generateJWT(String cardToken) throws Exception {
        
        Map jwtHeader = new HashMap<>();
        jwtHeader.put("typ", "JWT");
        jwtHeader.put("alg", "HS256");
        String encodedHeader = base64UrlEncode(gson.toJson(jwtHeader));
        
        Map jwtPayload = new HashMap<>();
        jwtPayload.put("mobicard_version", mobicardVersion);
        jwtPayload.put("mobicard_mode", mobicardMode);
        jwtPayload.put("mobicard_merchant_id", mobicardMerchantId);
        jwtPayload.put("mobicard_api_key", mobicardApiKey);
        jwtPayload.put("mobicard_service_id", mobicardServiceId);
        jwtPayload.put("mobicard_service_type", mobicardServiceType);
        jwtPayload.put("mobicard_token_id", mobicardTokenId);
        jwtPayload.put("mobicard_txn_reference", mobicardTxnReference);
        jwtPayload.put("mobicard_card_token", cardToken);
        
        String encodedPayload = base64UrlEncode(gson.toJson(jwtPayload));
        
        String headerPayload = encodedHeader + "." + encodedPayload;
        String signature = generateHMAC(headerPayload, mobicardSecretKey);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }
    
    public JsonObject detokenize(String cardToken) throws Exception {
        
        String jwtToken = generateJWT(cardToken);
        
        HttpClient client = HttpClient.newHttpClient();
        
        Map requestBody = new HashMap<>();
        requestBody.put("mobicard_auth_jwt", jwtToken);
        
        String jsonBody = gson.toJson(requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://mobicardsystems.com/api/v1/card_tokenization"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        
        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        return gson.fromJson(response.body(), JsonObject.class);
    }
    
    private String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes());
    }
    
    private String generateHMAC(String data, String key) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] hmacBytes = sha256Hmac.doFinal(data.getBytes());
        return base64UrlEncode(new String(hmacBytes));
    }
    
    public static void main(String[] args) {
        try {
            MobicardDetokenization detokenizer = new MobicardDetokenization(
                "",
                "",
                ""
            );
            
            // Token from your database
            String cardToken = "bbaefff665082af8f3a41fa51853062b1628345cec085498bba97e3ae3b1e77e4f7ac5ee0ac9bbf10ff8c151d006d80212a3dac731c48188a9e00f9084b163bf";
            
            JsonObject result = detokenizer.detokenize(cardToken);
            
            if (result.has("status")) {
                String status = result.get("status").getAsString();
                
                if ("SUCCESS".equals(status)) {
                    System.out.println("Detokenization Successful!");
                    
                    if (result.has("card_information")) {
                        JsonObject cardInfo = result.getAsJsonObject("card_information");
                        
                        System.out.println("Card Number: " + 
                            cardInfo.get("card_number_masked").getAsString());
                        System.out.println("Expiry Date: " + 
                            cardInfo.get("card_expiry_date").getAsString());
                        
                        // Check if single-use token flag is set
                        if (result.has("mobicard_single_use_token_flag")) {
                            String singleUseFlag = result.get("mobicard_single_use_token_flag").getAsString();
                            if ("1".equals(singleUseFlag)) {
                                System.out.println("New Token Generated: " + 
                                    cardInfo.get("card_token").getAsString());
                                System.out.println("Update your database with the new token.");
                            }
                        }
                        
                        // Use cardInfo.get("card_number").getAsString() for payment processing
                    }
                } else {
                    System.out.println("Detokenization Failed!");
                    if (result.has("status_message")) {
                        System.out.println("Error: " + result.get("status_message").getAsString());
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
