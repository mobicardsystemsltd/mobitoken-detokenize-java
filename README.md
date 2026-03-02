# Detokenization API Overview

Convert a secure token back to the original card data for payment processing. The token must have been previously generated through the Tokenization API.
> Use Case: When you need to process a payment, detokenize the stored token to retrieve the original card details for transaction processing.

> Single-Use Tokens: If the token was created with mobicard_single_use_token_flag = "1", a new token will be generated and returned after detokenization.

## Detokenization Implementation

Generate a signed JWT token with embedded request.

Send the card token to retrieve the original card details. For single-use tokens, a new token will be returned.

### Success Response Format

Both Tokenization and Detokenization APIs return the same success response format.
```json
{
  "status": "SUCCESS",
  "status_code": "200",
  "status_message": "SUCCESS",
  "mobicard_txn_reference": "998470530",
  "mobicard_single_use_token_flag": "0",
  "mobicard_custom_one": "mobicard_custom_one",
  "mobicard_custom_two": "mobicard_custom_two",
  "mobicard_custom_three": "mobicard_custom_three",
  "timestamp": "2026-01-26 13:25:29",
  "card_information": {
    "card_number": "4242424242424242",
    "card_number_masked": "4242********4242",
    "card_expiry_date": "02/28",
    "card_expiry_month": "02",
    "card_expiry_year": "28",
    "card_token": "bbaefff665082af8f3a41fa51853062b1628345cec085498bba97e3ae3b1e77e4f7ac5ee0ac9bbf10ff8c151d006d80212a3dac731c48188a9e00f9084b163bf"
  },
  "addendum_data": "your_custom_data_here_will_be_returned_as_is"
}
```
 Response Fields Explanation:

   * status: Always "SUCCESS" or "FAILED" - use this to determine subsequent actions
   * status_code: HTTP status code (200 for success)
   * card_number_masked: Masked card number for display purposes
   * card_token: Secure token to store instead of actual card data
   * mobicard_single_use_token_flag: "1" if token is single-use, "0" if multi-use
   * addendum_data: Custom data echoed back from request
   * mobicard_custom_one: Custom fields : One, Two & Three may be used to store extra info such as card-holder name etc
     
### Error Response Format

Error responses have a simplified format with only 3 fields of essential information.

Use the "status" field to determine if any API request is successful or not. The value is always either "SUCCESS" or "FAILED".
```json
{
  "status": "FAILED",
  "status_code": "400",
  "status_message": "BAD REQUEST"
}
```
### Status Codes Reference

Complete list of status codes returned by the API.
| Status Code | Status | Status Message Interpretation | Action Required |
| :--- | :--- | :--- | :--- |
| 200 | SUCCESS | SUCCESS | Process the response data |
| 400 | FAILED | BAD REQUEST - Invalid parameters or malformed request | Check request parameters |
| 429 | FAILED | TOO MANY REQUESTS - Rate limit exceeded | Wait before making more requests |
| 250 | FAILED | INSUFFICIENT TOKENS - Token account balance insufficient | Top up your account |
| 500 | FAILED | UNAVAILABLE - Server error | Try again later or contact support |
| 430 | FAILED | TIMEOUT - Request timed out | Issue new token and retry |

### API Request Parameters Reference

Complete reference of all request parameters used in the Tokenization API.
| Parameter | Required | Tokenization | Detokenization | Description | Example Value |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `mobicard_version` | **Yes** | ✓ | ✓ | API version | "2.0" |
| `mobicard_mode` | **Yes** | ✓ | ✓ | Environment mode | "TEST" or "LIVE" |
| `mobicard_merchant_id` | **Yes** | ✓ | ✓ | Your merchant ID | "YOUR_MERCHANT_ID" |
| `mobicard_api_key` | **Yes** | ✓ | ✓ | Your API key | "YOUR_API_KEY" |
| `mobicard_secret_key` | **Yes** | ✓ | ✓ | Your secret key | "YOUR_SECRET_KEY" |
| `mobicard_service_id` | **Yes** | ✓ | ✓ | Service ID | "20000" |
| `mobicard_service_type` | **Yes** | ✓ | ✓ | Service type | "TOKENIZATION" or "DETOKENIZATION" |
| `mobicard_token_id` | **Yes** | ✓ | ✓ | Unique token identifier | String/number |
| `mobicard_txn_reference` | **Yes** | ✓ | ✓ | Your transaction reference | String/number |
| `mobicard_single_use_token_flag` | Tokenization only | ✓ | | Single-use token flag | "0" or "1" |
| `mobicard_card_number` | Tokenization only | ✓ | | Card number to tokenize | "4242424242424242" |
| `mobicard_card_expiry_month` | Tokenization only | ✓ | | Card expiry month (MM) | "02" |
| `mobicard_card_expiry_year` | Tokenization only | ✓ | | Card expiry year (YY) | "28" |
| `mobicard_card_token` | Detokenization only | | ✓ | Token to detokenize | "bbaefff665082af8f3a..." |
| `mobicard_custom_one` | No | ✓ | | Custom data field 1 | Any string |
| `mobicard_custom_two` | No | ✓ | | Custom data field 2 | Any string |
| `mobicard_custom_three` | No | ✓ | | Custom data field 3 | Any string |
| `mobicard_extra_data` | No | ✓ | | Custom data returned in response | Any string |

### API Response Parameters Reference

Complete reference of all response parameters returned by the API.

The value for the "status" response parameter is always either "SUCCESS" or "FAILED". Use this to determine subsequent actions.
| Parameter | Always Returned | Description | Example Value |
| :--- | :---: | :--- | :--- |
| `status` | **Yes** | Transaction status | "SUCCESS" or "FAILED" |
| `status_code` | **Yes** | HTTP status code | "200" |
| `status_message` | **Yes** | Status description | "SUCCESS" |
| `mobicard_txn_reference` | **Yes** | Your original transaction reference | "998470530" |
| `mobicard_single_use_token_flag` | **Yes** | Single-use token flag from request | "0" or "1" |
| `timestamp` | **Yes** | Response timestamp | "2026-01-26 13:25:29" |
| `card_information.card_number` | **Yes** | Full card number (Detokenization only) | "4242424242424242" |
| `card_information.card_number_masked` | **Yes** | Masked card number (for display) | "4242********4242" |
| `card_information.card_expiry_date` | **Yes** | Card expiry in MM/YY format | "02/28" |
| `card_information.card_expiry_month` | **Yes** | Expiry month (2 digits) | "02" |
| `card_information.card_expiry_year` | **Yes** | Expiry year (2 digits) | "28" |
| `card_information.card_token` | **Yes** | Secure card token | "bbaefff665082af8f3a..." |
| `mobicard_custom_one` | If sent | Custom data field 1 echoed back | "custom_value_1" |
| `mobicard_custom_two` | If sent | Custom data field 2 echoed back | "custom_value_2" |
| `mobicard_custom_three` | If sent | Custom data field 3 echoed back | "custom_value_3" |
| `addendum_data` | If sent | Custom data echoed back from request | "your_custom_data_here" |
