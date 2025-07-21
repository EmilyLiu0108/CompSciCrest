import hashlib 
from ecdsa_utils import generate_keys, sign_data, verify_signature
import json
import time

class Block:
    def __init__(self,index,data,previousHash,nonce=0):
        self.index = index
        self.data = data
        self.previousHash = previousHash
        self.nonce = nonce
        self.timestamp = time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.data}{self.previousHash}{self.nonce}{self.timestamp}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def __str__(self):
        return (
            f"Block #{self.index}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Data: {self.data}\n"
            f"Previous Hash: {self.previousHash}\n"
            f"Nonce: {self.nonce}\n"
            f"Hash: {self.hash}\n"
        )



class Blockchain:
    #constructor
    def __init__(self):
        self.chain = [self.create_genesis_block()]
 
    #method to create the genesis block
    def create_genesis_block(self):
        return Block(0, "Genesis Block - PATIENT RECORD HASH", "0")

    def add_block(self, data):
        previous_block = self.get_latest_block()
        new_index = previous_block.index + 1
        new_block = Block(new_index, data, previous_block.hash)
        self.chain.append(new_block)
    
    
    def get_latest_block(self):
        return self.chain[-1] 
    
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previousHash != previous_block.hash:
                return False
        
        return True
    


if __name__ == "__main__":
    from ecdsa_utils import generate_keys, sign_data, verify_signature
    import json
    # Example usage
    genesis_block = Block(0, "Genesis Block - PATIENT RECORD HASH", "0")
    print(genesis_block)

    second_block = Block(1, "Second Block - PRESCRIPTION RECORD HASH", genesis_block.hash)
    print(second_block)

    third_block = Block(2, "Third Block - LAB RESULTS HASH", second_block.hash)
    print(third_block)
    my_chain = Blockchain()

    my_chain.add_block("Prescription Record Hash")
    my_chain.add_block("Lab Test Result Hash")
    my_chain.add_block("Discharge Summary Hash")

    # Print the chain
    for block in my_chain.chain:
        print(block)

    # Validate chain
    print("Is blockchain valid?", my_chain.is_chain_valid())


    # Generate keys for doctor
    doctor_private_key, doctor_public_key = generate_keys()

    #Create a sample patient record
    patient_record = {
        "patient_id": "654321",
        "name": "Sophie Scott",
        "age": 40,
        "medical_history": "Very pregnant",
        "prescription": "Pregnant vitamins",
        "lab_results": "Blood test normal",
        "timestamp": "2025-07-20"
    }

    record_str = json.dumps(record,soer_keys=True)
    record_has = hashlib.sha256(record_str.encode()).hexdigest()

    # doctor signs the patient record
    signature = sign_data(record_hash, doctor_private_key)

    #verify the signature
    valid = verify_signature(record_hash,signature, doctor_public_key)

    print("Original Record:", record)
    print("Record Hash:", record_hash)
    print("Signature:", signature)
    print("Signature Valid?", valid)
 
    # Add the signed record to the blockchain
    data_to_store = {
    "record_hash": record_hash,
    "signature": signature,
    "signer_public_key": doctor_public_key.to_string().hex()  # (optional for verification later)
    }
    my_chain.add_block(json.dumps(data_to_store))