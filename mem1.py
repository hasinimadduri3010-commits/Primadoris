import pickle

# ==========================================
# 1. GENERATE THE SAFE MODEL
# ==========================================
# This is a normal, harmless Python dictionary acting as a fake AI model.
safe_data = {
    "model_name": "Hackathon_Model_v1",
    "weights": [0.5, 0.8, 0.1, 0.9]
}

# Save it to a file
with open("safe_model.pkl", "wb") as f:
    pickle.dump(safe_data, f)
print("✅ safe_model.pkl generated successfully.")


# ==========================================
# 2. GENERATE THE "MALICIOUS" TEST MODEL
# ==========================================
# We create a special class that tells Python how to unpack it using __reduce__.
class MockMaliciousPayload:
    def __reduce__(self):
        # Instead of using 'os.system' (which gets blocked by filters),
        # we use 'eval' to do simple math. 
        # Real hackers use this exact same structure for dangerous commands.
        # Your scanner will see 'eval' in the bytecode and flag it!
        return (eval, ("1 + 1",))

# Create an instance of our fake malware
fake_malware = MockMaliciousPayload()

# Save it to a file
with open("malicious_model.pkl", "wb") as f:
    pickle.dump(fake_malware, f)
print("🚨 malicious_model.pkl generated successfully.")