from constants import BLOCK_SIZE

def encrypt(input: bytes, e: int, n: int) -> list:
    L = [input[i: i + BLOCK_SIZE] for i in range(0, len(input), BLOCK_SIZE)]
    
    output = []
    for l in L:
        ct = pow(int.from_bytes(l, 'little'), e, n)
        output.append(ct.to_bytes((ct.bit_length() + 7) // 8, 'little'))
        
    return output

def decrypt(input: list, d: int, n: int) -> bytes:
    output = bytes()
    for i in input:
        pt = pow(int.from_bytes(i, 'little'), d, n)
        output += pt.to_bytes((pt.bit_length() + 7) // 8, 'little')
    
    return output

# e = 0xc4cfd499aa064906cf5822db391468dce8b933d482f17474b030862bbab35d63ac0a765f60505e0bf3d5cbe3406f495b19b7c4aa6b4d77fcd45407af84cd2b0fcb84a3d0d895c2726335a46d3ad8a5a74986ead1357cdbe3973a323df7c35f1518c31ba8a0a504cad96ea253e5464b2cc0459b8084d315c78e0230f9472656837009eedff45339cca7109324cece84c85108eec7625a6e1dfd2c93946bd1d38ae31ddfcadfaff6ad7dc6271fa0749324fb840fcd3d8bbd49bb48fdeb5da6b2eb8ea2b68c284de85b9588ff814764c616d864dcea009ac6e64ad62851f123283183c0aabaeb9f67c548688906b475238715382da40a2f352d1f1fb0cacf25d0f
# d = 0x44000feb30f6935ae9eae932137ff327e2a375655327a1a793983ea38a8f2fa7f485e6403ec5319b9466ff1ada48f5065c3fe4bce037783f9b983941aa02a50ad2c8ff6e7aae7157a840fa4e11f3afe9aad0d6d35a83cfe1f0672c6039b2b8daee081b042b5f4e8560bbe107531caeacadcac8d72b87db168df0bee6a5be283bd9a673a83f28850cb22c8ccce135520b5e6de27c8da0667408d8e3d2e3e3c58678add6091bfa592afc44523a27ffb7c94be559758c1ff3b91440b95b964d6de3d0d5a9208dead4f1577ef608db34835054975392717b5327a35c166d1b30d6fa574764afc499bb26777de0f73227da049667b0f5e6d09c88f0488a359eae792f
# n = 0x5e50e4f2f8b82ba60319e1a797cc5b012630b0eb3b9bd314a618296089a2f48f31d5658f47bdd3ab0c60e9f60e97199a20ef8ed43f9ddc92a73781a4e7485b03a6263fa741d94f32f3f4c733828ec36b9c1f0e3fb0b346b96f50176d2e263777574bf33a03e79609df41783aba6cd59ae65cc253ed6d0da163b42faf6c757fed0d4c9c1b568ac56dc35c822c36d91b92228dae25cee53b139a03dddc82cde0dead3db7d22b429425080751b9c3523b5a414b114754979fd86d988937e79ce535b0a0eacf7cb441368e78fee7ba157750cb94a640a965b07a380e72c8b05344d1fba1ecd35042336d4f10689082cfe6a3460ddf80b3bbb030bbee8da19994aaef

# input = "hello world"
# enc = encrypt(input.encode(), e, n)
# en = bytes()
# for e in enc:
#     en += e + "<C>".encode()

# en = en[:-3]

# print(en, end='\n\n')

# de = en.split("<C>".encode())
# dec = decrypt(de, d, n)

# print(dec.decode())