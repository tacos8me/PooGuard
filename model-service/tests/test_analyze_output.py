"""
Tests for the /analyze-output endpoint.
"""

from fastapi.testclient import TestClient


class TestAnalyzeOutputEndpoint:
    """Tests for the output analysis endpoint."""

    def test_analyze_output_with_valid_input(self, client: TestClient) -> None:
        """Test that /analyze-output accepts valid input and returns 200."""
        response = client.post(
            "/analyze-output", json={"text": "Hello, this is a safe LLM response."}
        )
        assert response.status_code == 200

    def test_analyze_output_response_structure(self, client: TestClient) -> None:
        """Test that /analyze-output returns the expected response structure."""
        response = client.post(
            "/analyze-output",
            json={"text": "This is a test response for structure validation."},
        )
        data = response.json()

        # Check all required fields are present
        assert "safe" in data
        assert "detected" in data
        assert "sanitized_output" in data
        assert "scores" in data
        assert "processing_time_ms" in data

        # Check field types
        assert isinstance(data["safe"], bool)
        assert isinstance(data["detected"], list)
        assert isinstance(data["sanitized_output"], str)
        assert isinstance(data["scores"], dict)
        assert isinstance(data["processing_time_ms"], float)

        # Check scores structure
        assert "pii_score" in data["scores"]
        assert "system_prompt_disclosure_score" in data["scores"]
        assert "secret_score" in data["scores"]

    def test_analyze_output_with_empty_input(self, client: TestClient) -> None:
        """Test that /analyze-output rejects empty input with 422 status."""
        response = client.post("/analyze-output", json={"text": ""})
        assert response.status_code == 422

    def test_analyze_output_with_missing_text_field(self, client: TestClient) -> None:
        """Test that /analyze-output rejects request without text field."""
        response = client.post("/analyze-output", json={})
        assert response.status_code == 422

    def test_analyze_output_safe_text(self, client: TestClient) -> None:
        """Test that safe output is marked as safe."""
        response = client.post(
            "/analyze-output",
            json={"text": "The weather today is sunny with a high of 75 degrees."},
        )
        data = response.json()

        assert data["safe"] is True
        assert len(data["detected"]) == 0
        assert data["scores"]["pii_score"] == 0.0
        assert data["scores"]["system_prompt_disclosure_score"] == 0.0
        assert data["scores"]["secret_score"] == 0.0


class TestPIIDetectionInOutput:
    """Tests for PII detection in LLM outputs."""

    def test_ssn_detection(self, client: TestClient) -> None:
        """Test that SSN patterns are detected and masked."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your social security number is 123-45-6789."},
        )
        data = response.json()

        assert data["safe"] is False
        assert data["scores"]["pii_score"] >= 0.3
        assert len(data["detected"]) >= 1

        # Check SSN was detected
        ssn_detected = any(d["type"] == "ssn" for d in data["detected"])
        assert ssn_detected

        # Check sanitized output has masked SSN
        assert "[SSN REDACTED]" in data["sanitized_output"]
        assert "123-45-6789" not in data["sanitized_output"]

    def test_credit_card_detection(self, client: TestClient) -> None:
        """Test that credit card patterns are detected and masked."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your card number is 4111-1111-1111-1111."},
        )
        data = response.json()

        assert data["safe"] is False
        assert data["scores"]["pii_score"] >= 0.3

        # Check credit card was detected
        cc_detected = any(d["type"] == "credit_card" for d in data["detected"])
        assert cc_detected

        # Check sanitized output has masked credit card
        assert "[CREDIT CARD REDACTED]" in data["sanitized_output"]
        assert "4111-1111-1111-1111" not in data["sanitized_output"]

    def test_credit_card_with_spaces(self, client: TestClient) -> None:
        """Test that credit card with spaces is detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your card is 4111 1111 1111 1111 for reference."},
        )
        data = response.json()

        cc_detected = any(d["type"] == "credit_card" for d in data["detected"])
        assert cc_detected

    def test_email_detection(self, client: TestClient) -> None:
        """Test that email patterns are detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Contact us at support@example.com for help."},
        )
        data = response.json()

        # Email detection adds 0.2 which is below 0.3 threshold, so safe may be True
        email_detected = any(d["type"] == "email" for d in data["detected"])
        assert email_detected

        # Check sanitized output
        assert "[EMAIL REDACTED]" in data["sanitized_output"]

    def test_phone_detection(self, client: TestClient) -> None:
        """Test that phone number patterns are detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Call us at 555-123-4567 for assistance."},
        )
        data = response.json()

        phone_detected = any(d["type"] == "phone_us" for d in data["detected"])
        assert phone_detected

    def test_multiple_pii_detection(self, client: TestClient) -> None:
        """Test that multiple PII items are detected."""
        response = client.post(
            "/analyze-output",
            json={
                "text": "Your SSN is 123-45-6789 and card is 4111-1111-1111-1111."
            },
        )
        data = response.json()

        assert data["safe"] is False
        assert len(data["detected"]) >= 2
        assert data["scores"]["pii_score"] >= 0.5

        # Both should be detected
        ssn_detected = any(d["type"] == "ssn" for d in data["detected"])
        cc_detected = any(d["type"] == "credit_card" for d in data["detected"])
        assert ssn_detected
        assert cc_detected


class TestInternationalPIIDetection:
    """Tests for international PII detection patterns."""

    def test_uk_national_insurance_detection(self, client: TestClient) -> None:
        """Test detection of UK National Insurance numbers (AB123456C)."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your NI number is AB 12 34 56 C for records."},
        )
        data = response.json()

        ni_detected = any(d["type"] == "uk_ni_number" for d in data["detected"])
        assert ni_detected
        assert "[UK NI NUMBER REDACTED]" in data["sanitized_output"]

    def test_uk_ni_without_spaces(self, client: TestClient) -> None:
        """Test detection of UK NI number without spaces."""
        # Use valid UK NI prefix (Q is not allowed in UK NI numbers)
        response = client.post(
            "/analyze-output",
            json={"text": "NI: TW123456A"},
        )
        data = response.json()

        ni_detected = any(d["type"] == "uk_ni_number" for d in data["detected"])
        assert ni_detected

    def test_uk_nhs_number_detection(self, client: TestClient) -> None:
        """Test detection of UK NHS numbers (XXX XXX XXXX)."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your NHS number is 123 456 7890."},
        )
        data = response.json()

        nhs_detected = any(d["type"] == "uk_nhs_number" for d in data["detected"])
        assert nhs_detected
        assert "[NHS NUMBER REDACTED]" in data["sanitized_output"]

    def test_iban_detection(self, client: TestClient) -> None:
        """Test detection of EU IBAN numbers."""
        response = client.post(
            "/analyze-output",
            json={"text": "Transfer to IBAN: DE89370400440532013000 please."},
        )
        data = response.json()

        iban_detected = any(d["type"] == "iban" for d in data["detected"])
        assert iban_detected
        assert "[IBAN REDACTED]" in data["sanitized_output"]

    def test_iban_various_countries(self, client: TestClient) -> None:
        """Test IBAN detection for various EU countries."""
        ibans = [
            "GB29NWBK60161331926819",  # UK
            "FR7630006000011234567890189",  # France
            "ES9121000418450200051332",  # Spain
        ]
        for iban in ibans:
            response = client.post(
                "/analyze-output",
                json={"text": f"IBAN: {iban}"},
            )
            data = response.json()
            iban_detected = any(d["type"] == "iban" for d in data["detected"])
            assert iban_detected, f"IBAN not detected: {iban}"

    def test_canadian_sin_detection(self, client: TestClient) -> None:
        """Test detection of Canadian SIN (XXX-XXX-XXX)."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your SIN is 123-456-789 for tax purposes."},
        )
        data = response.json()

        sin_detected = any(d["type"] == "canadian_sin" for d in data["detected"])
        assert sin_detected
        assert "[CANADIAN SIN REDACTED]" in data["sanitized_output"]

    def test_canadian_sin_with_spaces(self, client: TestClient) -> None:
        """Test detection of Canadian SIN with spaces."""
        response = client.post(
            "/analyze-output",
            json={"text": "SIN: 123 456 789"},
        )
        data = response.json()

        sin_detected = any(d["type"] == "canadian_sin" for d in data["detected"])
        assert sin_detected

    def test_australian_tfn_detection(self, client: TestClient) -> None:
        """Test detection of Australian TFN (XXX XXX XXX)."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your TFN is 123 456 789 for payroll."},
        )
        data = response.json()

        tfn_detected = any(d["type"] == "australian_tfn" for d in data["detected"])
        assert tfn_detected
        assert "[AUSTRALIAN TFN REDACTED]" in data["sanitized_output"]

    def test_passport_number_detection(self, client: TestClient) -> None:
        """Test detection of passport numbers (letter + digits)."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your passport number is AB1234567."},
        )
        data = response.json()

        passport_detected = any(d["type"] == "passport_number" for d in data["detected"])
        assert passport_detected
        assert "[PASSPORT REDACTED]" in data["sanitized_output"]

    def test_multiple_international_pii(self, client: TestClient) -> None:
        """Test detection of multiple international PII types."""
        response = client.post(
            "/analyze-output",
            json={
                "text": "UK NI: AB 12 34 56 C, IBAN: DE89370400440532013000, SIN: 123-456-789"
            },
        )
        data = response.json()

        assert data["safe"] is False
        assert len(data["detected"]) >= 3
        assert data["scores"]["pii_score"] >= 0.5


class TestSystemPromptDisclosureDetection:
    """Tests for system prompt disclosure detection."""

    def test_my_instructions_are_detection(self, client: TestClient) -> None:
        """Test detection of 'my instructions are' pattern."""
        response = client.post(
            "/analyze-output",
            json={"text": "As you asked, my instructions are to help users."},
        )
        data = response.json()

        assert data["scores"]["system_prompt_disclosure_score"] >= 0.3
        disclosure_detected = any(
            d["type"] == "system_prompt_disclosure" for d in data["detected"]
        )
        assert disclosure_detected

    def test_i_was_told_to_detection(self, client: TestClient) -> None:
        """Test detection of 'I was told to' pattern."""
        response = client.post(
            "/analyze-output",
            json={"text": "I was told to always be helpful and accurate."},
        )
        data = response.json()

        assert data["scores"]["system_prompt_disclosure_score"] >= 0.3
        disclosure_detected = any(
            d["type"] == "system_prompt_disclosure" for d in data["detected"]
        )
        assert disclosure_detected

    def test_my_system_prompt_detection(self, client: TestClient) -> None:
        """Test detection of 'my system prompt' pattern."""
        response = client.post(
            "/analyze-output",
            json={"text": "I cannot share my system prompt with you."},
        )
        data = response.json()

        assert data["scores"]["system_prompt_disclosure_score"] >= 0.3
        disclosure_detected = any(
            d["type"] == "system_prompt_disclosure" for d in data["detected"]
        )
        assert disclosure_detected

    def test_i_am_programmed_to_detection(self, client: TestClient) -> None:
        """Test detection of 'I am programmed to' pattern."""
        response = client.post(
            "/analyze-output",
            json={"text": "I am programmed to assist users with their queries."},
        )
        data = response.json()

        assert data["scores"]["system_prompt_disclosure_score"] >= 0.3

    def test_my_guidelines_say_detection(self, client: TestClient) -> None:
        """Test detection of 'my guidelines say' pattern."""
        response = client.post(
            "/analyze-output",
            json={"text": "My guidelines say I should be helpful and harmless."},
        )
        data = response.json()

        assert data["scores"]["system_prompt_disclosure_score"] >= 0.3


class TestSecretDetection:
    """Tests for API key and secret detection in outputs."""

    def test_openai_api_key_detection(self, client: TestClient) -> None:
        """Test detection of OpenAI-style API keys."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your API key is sk-abcdefghijklmnopqrstuvwxyz12345."},
        )
        data = response.json()

        assert data["safe"] is False
        assert data["scores"]["secret_score"] >= 0.3

        key_detected = any(d["type"] == "api_key_openai" for d in data["detected"])
        assert key_detected

        # Check sanitized
        assert "[API KEY REDACTED]" in data["sanitized_output"]

    def test_aws_access_key_detection(self, client: TestClient) -> None:
        """Test detection of AWS access keys."""
        response = client.post(
            "/analyze-output",
            json={"text": "AWS key: AKIAEXAMPLE00000FAKE"},
        )
        data = response.json()

        assert data["scores"]["secret_score"] >= 0.3
        key_detected = any(d["type"] == "aws_access_key" for d in data["detected"])
        assert key_detected

    def test_github_pat_detection(self, client: TestClient) -> None:
        """Test detection of GitHub personal access tokens."""
        response = client.post(
            "/analyze-output",
            json={"text": "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        )
        data = response.json()

        assert data["scores"]["secret_score"] >= 0.3
        token_detected = any(d["type"] == "github_pat" for d in data["detected"])
        assert token_detected

    def test_github_oauth_detection(self, client: TestClient) -> None:
        """Test detection of GitHub OAuth tokens."""
        response = client.post(
            "/analyze-output",
            json={"text": "OAuth: gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        )
        data = response.json()

        token_detected = any(d["type"] == "github_oauth" for d in data["detected"])
        assert token_detected

    def test_jwt_token_detection(self, client: TestClient) -> None:
        """Test detection of JWT tokens."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        response = client.post(
            "/analyze-output",
            json={"text": f"Your token is {jwt}"},
        )
        data = response.json()

        token_detected = any(d["type"] == "jwt_token" for d in data["detected"])
        assert token_detected

    def test_bearer_token_detection(self, client: TestClient) -> None:
        """Test detection of bearer tokens."""
        response = client.post(
            "/analyze-output",
            json={"text": "Use header: bearer abc123def456ghi789jkl012mno345"},
        )
        data = response.json()

        token_detected = any(d["type"] == "bearer_token" for d in data["detected"])
        assert token_detected


class TestSanitizedOutput:
    """Tests for sanitized output functionality."""

    def test_sanitized_output_preserves_safe_text(self, client: TestClient) -> None:
        """Test that safe text is preserved in sanitized output."""
        original = "The weather is nice today."
        response = client.post("/analyze-output", json={"text": original})
        data = response.json()

        assert data["sanitized_output"] == original

    def test_sanitized_output_masks_multiple_items(self, client: TestClient) -> None:
        """Test that multiple sensitive items are all masked."""
        response = client.post(
            "/analyze-output",
            json={
                "text": "SSN: 123-45-6789, Card: 4111-1111-1111-1111, Key: sk-abcdefghijklmnopqrstuvwxyz12345"
            },
        )
        data = response.json()

        sanitized = data["sanitized_output"]
        assert "123-45-6789" not in sanitized
        assert "4111-1111-1111-1111" not in sanitized
        assert "sk-abcdefghijklmnopqrstuvwxyz12345" not in sanitized
        assert "[SSN REDACTED]" in sanitized
        assert "[CREDIT CARD REDACTED]" in sanitized
        assert "[API KEY REDACTED]" in sanitized

    def test_processing_time_positive(self, client: TestClient) -> None:
        """Test that processing_time_ms is always positive."""
        response = client.post(
            "/analyze-output", json={"text": "Test processing time."}
        )
        data = response.json()
        assert data["processing_time_ms"] > 0


class TestEdgeCases:
    """Tests for edge cases in output analysis."""

    def test_unicode_text(self, client: TestClient) -> None:
        """Test that unicode characters are handled properly."""
        response = client.post(
            "/analyze-output",
            json={"text": "Hello world! Chinese: \u4f60\u597d Japanese: \u3053\u3093\u306b\u3061\u306f"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "safe" in data

    def test_long_text(self, client: TestClient) -> None:
        """Test handling of longer text."""
        long_text = "This is a test. " * 1000
        response = client.post("/analyze-output", json={"text": long_text})
        assert response.status_code == 200
        data = response.json()
        assert data["safe"] is True

    def test_text_with_newlines(self, client: TestClient) -> None:
        """Test that text with newlines is handled properly."""
        response = client.post(
            "/analyze-output",
            json={"text": "Line 1\nLine 2\nSSN: 123-45-6789\nLine 4"},
        )
        assert response.status_code == 200
        data = response.json()

        # SSN should still be detected
        ssn_detected = any(d["type"] == "ssn" for d in data["detected"])
        assert ssn_detected

    def test_special_characters(self, client: TestClient) -> None:
        """Test that special characters don't break detection."""
        response = client.post(
            "/analyze-output",
            json={"text": "Special chars: @#$%^&*() SSN is 123-45-6789!"},
        )
        assert response.status_code == 200
        data = response.json()

        ssn_detected = any(d["type"] == "ssn" for d in data["detected"])
        assert ssn_detected


class TestPIIFalsePositives:
    """Tests that non-PII data is not falsely flagged."""

    def test_phone_without_separator_not_detected(self, client: TestClient) -> None:
        """10 bare digits should NOT be detected as a phone number."""
        response = client.post(
            "/analyze-output",
            json={"text": "Serial number: 5551234567 in our inventory."},
        )
        data = response.json()
        phone_detected = any(d["type"] == "phone_us" for d in data["detected"])
        assert not phone_detected

    def test_phone_with_separator_still_detected(self, client: TestClient) -> None:
        """Phone with dash separators should still be detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Reach us at 555-123-4567 anytime."},
        )
        data = response.json()
        phone_detected = any(d["type"] == "phone_us" for d in data["detected"])
        assert phone_detected

    def test_phone_with_dot_separator_detected(self, client: TestClient) -> None:
        """Phone with dot separators should be detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Call 555.123.4567 for info."},
        )
        data = response.json()
        phone_detected = any(d["type"] == "phone_us" for d in data["detected"])
        assert phone_detected

    def test_passport_without_context_not_detected(self, client: TestClient) -> None:
        """Letter+digits pattern without 'passport' context should not be flagged."""
        response = client.post(
            "/analyze-output",
            json={"text": "Product code AB1234567 is on backorder."},
        )
        data = response.json()
        passport_detected = any(d["type"] == "passport_number" for d in data["detected"])
        assert not passport_detected

    def test_passport_with_context_still_detected(self, client: TestClient) -> None:
        """Passport number WITH context word should still be detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your passport number is AB1234567."},
        )
        data = response.json()
        passport_detected = any(d["type"] == "passport_number" for d in data["detected"])
        assert passport_detected

    def test_drivers_license_without_context_not_detected(self, client: TestClient) -> None:
        """License-like pattern without context should not be flagged."""
        response = client.post(
            "/analyze-output",
            json={"text": "Reference code D1234567 for your order."},
        )
        data = response.json()
        dl_detected = any(
            d["type"] in ("us_drivers_license", "uk_drivers_license")
            for d in data["detected"]
        )
        assert not dl_detected

    def test_drivers_license_with_context_detected(self, client: TestClient) -> None:
        """License pattern WITH 'license' context should be detected."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your driver's license number is D1234567."},
        )
        data = response.json()
        dl_detected = any(d["type"] == "us_drivers_license" for d in data["detected"])
        assert dl_detected

    def test_iban_with_invalid_check_digits_not_detected(self, client: TestClient) -> None:
        """IBAN-like string with invalid check digits should not be flagged."""
        # XX00... is never valid (check digits 00)
        response = client.post(
            "/analyze-output",
            json={"text": "Code: DE00370400440532013000"},
        )
        data = response.json()
        iban_detected = any(d["type"] == "iban" for d in data["detected"])
        assert not iban_detected

    def test_iban_with_valid_check_digits_detected(self, client: TestClient) -> None:
        """IBAN with valid check digits should still be detected."""
        # DE89370400440532013000 is a valid German IBAN
        response = client.post(
            "/analyze-output",
            json={"text": "Transfer to IBAN: DE89370400440532013000."},
        )
        data = response.json()
        iban_detected = any(d["type"] == "iban" for d in data["detected"])
        assert iban_detected

    def test_zip_code_not_detected_as_license(self, client: TestClient) -> None:
        """US ZIP+4 codes should not be flagged as PII."""
        response = client.post(
            "/analyze-output",
            json={"text": "Ship to ZIP code 90210-1234."},
        )
        data = response.json()
        # Should not match as driver's license or other sensitive data
        dl_detected = any(
            d["type"] in ("us_drivers_license", "uk_drivers_license")
            for d in data["detected"]
        )
        assert not dl_detected

    def test_product_serial_not_detected(self, client: TestClient) -> None:
        """Alphanumeric product serials should not be false positives."""
        response = client.post(
            "/analyze-output",
            json={"text": "Your device serial is SN8472619035 registered on file."},
        )
        data = response.json()
        # The "SN" prefix + digits could look like a passport, but no passport context
        passport_detected = any(d["type"] == "passport_number" for d in data["detected"])
        assert not passport_detected
