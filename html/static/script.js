// Production-ready cryptographic functions for WireGuard key generation
// Uses TweetNaCl.js for proper Curve25519 operations and Web Crypto API for HKDF

class WireGuardCrypto {
    constructor() {
        this.crypto = window.crypto || window.msCrypto;
        
        // Check if TweetNaCl is available
        if (typeof nacl === 'undefined') {
            throw new Error('TweetNaCl library is required but not loaded');
        }
        
        // Check if Web Crypto API is available
        this.hasWebCrypto = !!(this.crypto && this.crypto.subtle);
        
        if (!this.hasWebCrypto) {
            console.warn('Web Crypto API not available, falling back to less secure methods');
        }
        
        // Key counter for deterministic key generation
        this.keyCounter = 0;
    }

    // Generate a cryptographically secure random seed
    generateSeed() {
        const array = new Uint8Array(32);
        this.crypto.getRandomValues(array);
        return array;
    }

    // HKDF implementation using Web Crypto API when available
    async hkdf(seed, salt, info, length = 32) {
        if (this.hasWebCrypto) {
            try {
                // Import the seed as key material
                const keyMaterial = await this.crypto.subtle.importKey(
                    'raw',
                    seed,
                    'HKDF',
                    false,
                    ['deriveBits']
                );

                // Derive key using HKDF
                const derivedBits = await this.crypto.subtle.deriveBits(
                    {
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: salt,
                        info: info
                    },
                    keyMaterial,
                    length * 8 // length in bits
                );

                return new Uint8Array(derivedBits);
            } catch (error) {
                console.warn('Web Crypto HKDF failed, falling back to HMAC-based implementation:', error);
                return this.hkdfFallback(seed, salt, info, length);
            }
        } else {
            return this.hkdfFallback(seed, salt, info, length);
        }
    }

    // Fallback HKDF implementation using TweetNaCl's hash function
    hkdfFallback(seed, salt, info, length = 32) {
        // HKDF-Extract
        const prk = this.hmacSha256(salt.length > 0 ? salt : new Uint8Array(32), seed);
        
        // HKDF-Expand
        const n = Math.ceil(length / 32);
        const okm = new Uint8Array(length);
        let t = new Uint8Array(0);
        
        for (let i = 1; i <= n; i++) {
            const concat = new Uint8Array(t.length + info.length + 1);
            concat.set(t);
            concat.set(info, t.length);
            concat[concat.length - 1] = i;
            
            t = this.hmacSha256(prk, concat);
            const copyLength = Math.min(32, length - (i - 1) * 32);
            okm.set(t.subarray(0, copyLength), (i - 1) * 32);
        }
        
        return okm;
    }

    // HMAC-SHA256 implementation using TweetNaCl
    hmacSha256(key, data) {
        const blockSize = 64;
        const hashSize = 32;
        
        // If key is longer than block size, hash it
        if (key.length > blockSize) {
            key = nacl.hash(key).subarray(0, hashSize);
        }
        
        // Pad key to block size
        const paddedKey = new Uint8Array(blockSize);
        paddedKey.set(key);
        
        // Create inner and outer padding
        const ipad = new Uint8Array(blockSize);
        const opad = new Uint8Array(blockSize);
        
        for (let i = 0; i < blockSize; i++) {
            ipad[i] = paddedKey[i] ^ 0x36;
            opad[i] = paddedKey[i] ^ 0x5c;
        }
        
        // Inner hash
        const innerData = new Uint8Array(blockSize + data.length);
        innerData.set(ipad);
        innerData.set(data, blockSize);
        const innerHash = nacl.hash(innerData);
        
        // Outer hash
        const outerData = new Uint8Array(blockSize + hashSize);
        outerData.set(opad);
        outerData.set(innerHash);
        
        return nacl.hash(outerData);
    }

    // Generate a WireGuard private key using proper key derivation
    async generatePrivateKey(seed) {
        const salt = new TextEncoder().encode('WireGuard v1 private key');
        const info = new Uint8Array(4);
        // Convert key counter to bytes (little endian)
        const keyIndex = this.keyCounter++;
        info[0] = keyIndex & 0xff;
        info[1] = (keyIndex >> 8) & 0xff;
        info[2] = (keyIndex >> 16) & 0xff;
        info[3] = (keyIndex >> 24) & 0xff;
        
        const keyMaterial = await this.hkdf(seed, salt, info, 32);
        
        // Apply Curve25519 key clamping as per RFC 7748
        keyMaterial[0] &= 248;   // Clear bottom 3 bits
        keyMaterial[31] &= 127;  // Clear top bit
        keyMaterial[31] |= 64;   // Set second-highest bit
        
        return this.arrayToBase64(keyMaterial);
    }

    // Generate public key from private key using real Curve25519 scalar multiplication
    generatePublicKey(privateKeyBase64) {
        try {
            const privateKeyBytes = this.base64ToArray(privateKeyBase64);
            
            // Use TweetNaCl's scalar multiplication with base point
            const publicKeyBytes = nacl.scalarMult.base(privateKeyBytes);
            
            return this.arrayToBase64(publicKeyBytes);
        } catch (error) {
            throw new Error('Failed to generate public key: ' + error.message);
        }
    }

    // Generate preshared key using proper key derivation
    async generatePresharedKey(seed) {
        const salt = new TextEncoder().encode('WireGuard v1 preshared key');
        const info = new Uint8Array(4);
        const keyIndex = this.keyCounter++;
        info[0] = keyIndex & 0xff;
        info[1] = (keyIndex >> 8) & 0xff;
        info[2] = (keyIndex >> 16) & 0xff;
        info[3] = (keyIndex >> 24) & 0xff;
        
        const keyMaterial = await this.hkdf(seed, salt, info, 32);
        return this.arrayToBase64(keyMaterial);
    }

    // Reset key counter for deterministic generation
    resetKeyCounter() {
        this.keyCounter = 0;
    }

    // Utility functions
    arrayToBase64(array) {
        return btoa(String.fromCharCode.apply(null, array));
    }

    base64ToArray(base64) {
        const binary = atob(base64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        return array;
    }

    arrayToHex(array) {
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    hexToArray(hex) {
        if (hex.length !== 64) {
            throw new Error('Hex string must be exactly 64 characters (32 bytes)');
        }
        const array = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            array[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return array;
    }

    // Parse seed from input (hex string or generate new)
    parseSeed(customSeedHex) {
        if (customSeedHex && customSeedHex.trim()) {
            return this.hexToArray(customSeedHex.trim());
        } else {
            return this.generateSeed();
        }
    }

    // Validate that generated keys are valid
    validateKeyPair(privateKeyBase64, publicKeyBase64) {
        try {
            const privateKey = this.base64ToArray(privateKeyBase64);
            const publicKey = this.base64ToArray(publicKeyBase64);
            
            // Check lengths
            if (privateKey.length !== 32 || publicKey.length !== 32) {
                console.warn('Invalid key length');
                return false;
            }
            
            // Check key clamping on private key
            if ((privateKey[0] & 7) !== 0 || (privateKey[31] & 128) !== 0 || (privateKey[31] & 64) === 0) {
                console.warn('Invalid key clamping');
                return false;
            }
            
            // Verify public key matches private key
            const derivedPublic = nacl.scalarMult.base(privateKey);
            
            for (let i = 0; i < 32; i++) {
                if (derivedPublic[i] !== publicKey[i]) {
                    console.warn('Public key does not match private key');
                    return false;
                }
            }
            
            return true;
        } catch (error) {
            console.error('Key validation error:', error);
            return false;
        }
    }

    // Get info about the crypto implementation
    getCryptoInfo() {
        return {
            library: 'TweetNaCl.js v1.0.3',
            hasWebCrypto: this.hasWebCrypto,
            curve: 'Curve25519 (X25519)',
            hkdf: this.hasWebCrypto ? 'Web Crypto API' : 'HMAC-SHA256 fallback',
            secure: true
        };
    }
}

let currentConfigs = null;
let currentSeed = null;
let currentMeshConfigs = null;

// Initialize crypto with error handling
let crypto;
try {
    crypto = new WireGuardCrypto();
    console.log('Crypto initialized:', crypto.getCryptoInfo());
} catch (error) {
    console.error('Failed to initialize crypto:', error);
    alert('Cryptographic library failed to initialize. Please refresh the page.');
}

async function generateConfigs() {
    try {
        const serverName = document.getElementById('serverName').value;
        const serverPort = parseInt(document.getElementById('serverPort').value);
        const serverNetwork = document.getElementById('serverNetwork').value;
        const serverEndpoint = document.getElementById('serverEndpoint').value;
        const clientCount = parseInt(document.getElementById('clientCount').value);
        const dns = document.getElementById('dns').value;

        // Validate inputs
        if (!validateInputs(serverNetwork, serverEndpoint, clientCount)) {
            return;
        }

        // Show loading state
        const generateBtn = document.querySelector('button[onclick="generateConfigs()"]');
        const originalText = generateBtn.textContent;
        generateBtn.textContent = 'Generating...';
        generateBtn.disabled = true;

        // Generate or use existing seed
        const customSeedHex = document.getElementById('customSeed').value;
        let seed;
        
        if (customSeedHex && customSeedHex.trim()) {
            // Use custom seed from input
            seed = crypto.parseSeed(customSeedHex);
        } else if (currentSeed) {
            // Use existing seed if available
            seed = currentSeed;
        } else {
            // Generate new seed only if none exists
            seed = crypto.generateSeed();
        }
        
        currentSeed = seed;
        
        // Update seed display and input field
        const seedHex = crypto.arrayToHex(seed);
        document.getElementById('seedDisplay').textContent = seedHex;
        if (!customSeedHex || !customSeedHex.trim()) {
            document.getElementById('customSeed').value = seedHex;
        }
        
        // Reset key counter for deterministic generation
        crypto.resetKeyCounter();

        // Generate server keys
        const serverPrivateKey = await crypto.generatePrivateKey(seed);
        const serverPublicKey = crypto.generatePublicKey(serverPrivateKey);

        // Parse network
        const [networkBase, cidr] = serverNetwork.split('/');
        const networkParts = networkBase.split('.').map(n => parseInt(n));
        
        // Generate client configurations
        const clients = [];
        for (let i = 1; i <= clientCount; i++) {
            const clientPrivateKey = await crypto.generatePrivateKey(seed);
            const clientPublicKey = crypto.generatePublicKey(clientPrivateKey);
            const presharedKey = await crypto.generatePresharedKey(seed);
            
            // Calculate client IP (server gets .1, clients get .2, .3, etc.)
            const clientIP = `${networkParts[0]}.${networkParts[1]}.${networkParts[2]}.${networkParts[3] + i}`;
            
            clients.push({
                name: `client-${i}`,
                privateKey: clientPrivateKey,
                publicKey: clientPublicKey,
                presharedKey: presharedKey,
                ip: clientIP
            });
        }

        // Generate configurations
        const serverConfig = generateServerConfig(serverName, serverPrivateKey, serverPort, 
            `${networkParts[0]}.${networkParts[1]}.${networkParts[2]}.${networkParts[3] + 1}`, 
            cidr, clients);

        const clientConfigs = clients.map(client => 
            generateClientConfig(client, serverPublicKey, serverEndpoint, serverPort, 
                `${networkParts[0]}.${networkParts[1]}.${networkParts[2]}.${networkParts[3] + 1}`, 
                cidr, dns)
        );

        // Store configurations
        currentConfigs = {
            server: serverConfig,
            clients: clientConfigs.map((config, index) => ({
                name: clients[index].name,
                config: config
            }))
        };

        // Display configurations
        displayConfigurations();

        // Restore button
        generateBtn.textContent = originalText;
        generateBtn.disabled = false;

    } catch (error) {
        // Restore button on error
        const generateBtn = document.querySelector('button[onclick="generateConfigs()"]');
        if (generateBtn) {
            generateBtn.textContent = 'Generate Configurations';
            generateBtn.disabled = false;
        }
        alert('Error generating configurations: ' + error.message);
    }
}

function validateInputs(serverNetwork, serverEndpoint, clientCount) {
    // Validate network CIDR
    const cidrRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/([1-2]?[0-9]|3[0-2])$/;
    if (!cidrRegex.test(serverNetwork)) {
        alert('Invalid network CIDR format');
        return false;
    }

    // Validate endpoint
    if (!serverEndpoint.trim()) {
        alert('Server endpoint is required');
        return false;
    }

    // Validate client count
    if (clientCount < 1 || clientCount > 50) {
        alert('Client count must be between 1 and 50');
        return false;
    }

    return true;
}

function generateServerConfig(name, privateKey, port, serverIP, cidr, clients) {
    let config = `# ${name} Configuration
[Interface]
PrivateKey = ${privateKey}
Address = ${serverIP}/${cidr}
ListenPort = ${port}
SaveConfig = true

# PostUp and PostDown rules for NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

`;

    clients.forEach(client => {
        config += `# ${client.name}
[Peer]
PublicKey = ${client.publicKey}
PresharedKey = ${client.presharedKey}
AllowedIPs = ${client.ip}/32

`;
    });

    return config;
}

function generateClientConfig(client, serverPublicKey, serverEndpoint, serverPort, serverIP, cidr, dns) {
    let config = `# ${client.name} Configuration
[Interface]
PrivateKey = ${client.privateKey}
Address = ${client.ip}/${cidr}`;
    
    // Only add DNS if it's not empty
    if (dns && dns.trim()) {
        config += `
DNS = ${dns.trim()}`;
    }
    
    config += `

[Peer]
PublicKey = ${serverPublicKey}
PresharedKey = ${client.presharedKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${serverEndpoint}:${serverPort}
PersistentKeepalive = 25
`;
    
    return config;
}

function displayConfigurations() {
    // Show server config
    document.getElementById('serverConfig').textContent = currentConfigs.server;
    
    // Generate client configs in row layout
    const clientConfigs = document.getElementById('clientConfigs');
    clientConfigs.innerHTML = '';
    
    currentConfigs.clients.forEach((client, index) => {
        // Create client config item
        const configItem = document.createElement('div');
        configItem.className = 'client-config-item';
        configItem.innerHTML = `
            <div class="client-config-title">${client.name}</div>
            <div class="config-content">${client.config}</div>
            <button class="download-btn" onclick="downloadConfig('${client.name}', \`${client.config.replace(/`/g, '\\`')}\`)">
                Download ${client.name} Config
            </button>
        `;
        clientConfigs.appendChild(configItem);
    });
    
    document.getElementById('configOutput').style.display = 'block';
}

function downloadConfig(name, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.conf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Seed management functions
function generateNewSeed() {
    const seed = crypto.generateSeed();
    currentSeed = seed;
    const hexSeed = crypto.arrayToHex(seed);
    document.getElementById('seedDisplay').textContent = hexSeed;
    document.getElementById('customSeed').value = hexSeed;
}

function copySeed() {
    if (currentSeed) {
        const hexSeed = crypto.arrayToHex(currentSeed);
        navigator.clipboard.writeText(hexSeed).then(() => {
            alert('Seed copied to clipboard!');
        }).catch(() => {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = hexSeed;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert('Seed copied to clipboard!');
        });
    } else {
        alert('No seed to copy. Generate configurations first.');
    }
}

function pasteSeed() {
    navigator.clipboard.readText().then(text => {
        if (text && text.length === 64 && /^[0-9a-fA-F]+$/.test(text)) {
            document.getElementById('customSeed').value = text;
            document.getElementById('seedDisplay').textContent = text;
            // Update current seed
            try {
                currentSeed = crypto.hexToArray(text);
                alert('Seed pasted successfully!');
            } catch (error) {
                alert('Invalid seed format.');
            }
        } else {
            alert('Invalid seed in clipboard. Must be 64-character hex string.');
        }
    }).catch(() => {
        alert('Cannot read from clipboard. Please paste manually into the Custom Seed field.');
    });
}

// Initialize form validation
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('configForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            generateConfigs();
        });
    }
    
    const meshForm = document.getElementById('meshConfigForm');
    if (meshForm) {
        meshForm.addEventListener('submit', function(e) {
            e.preventDefault();
            generateMeshConfigs();
        });
        
        // Initialize with default peer fields for mesh
        updatePeerFields();
    }
    
    // Validate custom seed input
    const customSeedInput = document.getElementById('customSeed');
    if (customSeedInput) {
        customSeedInput.addEventListener('input', function(e) {
            const value = e.target.value.trim();
            if (value && (value.length !== 64 || !/^[0-9a-fA-F]*$/.test(value))) {
                e.target.style.borderColor = '#dc3545';
            } else {
                e.target.style.borderColor = '#ddd';
                // Update current seed and display when valid seed is entered
                if (value && value.length === 64 && /^[0-9a-fA-F]+$/.test(value)) {
                    try {
                        currentSeed = crypto.hexToArray(value);
                        document.getElementById('seedDisplay').textContent = value;
                    } catch (error) {
                        console.warn('Invalid hex seed:', error);
                    }
                }
            }
        });
        
        // Handle clearing the custom seed input
        customSeedInput.addEventListener('keydown', function(e) {
            if (e.key === 'Delete' || e.key === 'Backspace') {
                // If user is clearing the field, don't update currentSeed immediately
                // Let them finish editing first
            }
        });
    }
});

// === MESH NETWORK FUNCTIONS ===

function updatePeerFields() {
    const peerCount = parseInt(document.getElementById('peerCount').value);
    const peerInputs = document.getElementById('peerInputs');
    
    if (peerCount < 2 || peerCount > 20) {
        alert('Number of peers must be between 2 and 20');
        return;
    }
    
    peerInputs.innerHTML = '';
    
    for (let i = 1; i <= peerCount; i++) {
        const peerGroup = document.createElement('div');
        peerGroup.className = 'peer-input-group';
        peerGroup.innerHTML = `
            <h4>Peer ${i}</h4>
            <div class="peer-row">
                <div class="form-group">
                    <label for="peerName${i}">Name:</label>
                    <input type="text" id="peerName${i}" value="peer-${i}" required>
                </div>
                <div class="form-group">
                    <label for="peerEndpoint${i}">Endpoint (optional):</label>
                    <input type="text" id="peerEndpoint${i}" placeholder="domain.com or IP address">
                </div>
                <div class="form-group">
                    <label for="peerPort${i}">Port:</label>
                    <input type="number" id="peerPort${i}" value="51820" min="1" max="65535" required>
                </div>
            </div>
        `;
        peerInputs.appendChild(peerGroup);
    }
}

async function generateMeshConfigs() {
    try {
        const networkCIDR = document.getElementById('networkCIDR').value;
        const dns = document.getElementById('dns').value;
        const peerCount = parseInt(document.getElementById('peerCount').value);

        // Validate inputs
        if (!validateMeshInputs(networkCIDR, peerCount)) {
            return;
        }

        // Show loading state
        const generateBtn = document.querySelector('button[onclick="generateMeshConfigs()"]');
        const originalText = generateBtn.textContent;
        generateBtn.textContent = 'Generating...';
        generateBtn.disabled = true;

        // Generate or use existing seed
        const customSeedHex = document.getElementById('customSeed').value;
        let seed;
        
        if (customSeedHex && customSeedHex.trim()) {
            // Use custom seed from input
            seed = crypto.parseSeed(customSeedHex);
        } else if (currentSeed) {
            // Use existing seed if available
            seed = currentSeed;
        } else {
            // Generate new seed only if none exists
            seed = crypto.generateSeed();
        }
        
        currentSeed = seed;
        
        // Update seed display and input field
        const seedHex = crypto.arrayToHex(seed);
        document.getElementById('seedDisplay').textContent = seedHex;
        if (!customSeedHex || !customSeedHex.trim()) {
            document.getElementById('customSeed').value = seedHex;
        }
        
        // Reset key counter for deterministic generation
        crypto.resetKeyCounter();

        // Parse network
        const [networkBase, cidr] = networkCIDR.split('/');
        const networkParts = networkBase.split('.').map(n => parseInt(n));

        // Collect peer information
        const peers = [];
        for (let i = 1; i <= peerCount; i++) {
            const name = document.getElementById(`peerName${i}`).value.trim();
            const endpoint = document.getElementById(`peerEndpoint${i}`).value.trim();
            const port = parseInt(document.getElementById(`peerPort${i}`).value);
            
            if (!name) {
                alert(`Peer ${i} name is required`);
                // Restore button
                generateBtn.textContent = originalText;
                generateBtn.disabled = false;
                return;
            }

            const privateKey = await crypto.generatePrivateKey(seed);
            const publicKey = crypto.generatePublicKey(privateKey);
            const ip = `${networkParts[0]}.${networkParts[1]}.${networkParts[2]}.${networkParts[3] + i}`;

            peers.push({
                name: name,
                privateKey: privateKey,
                publicKey: publicKey,
                endpoint: endpoint,
                port: port,
                ip: ip
            });
        }

        // Generate preshared keys for each pair of peers
        const presharedKeys = {};
        for (let i = 0; i < peers.length; i++) {
            for (let j = i + 1; j < peers.length; j++) {
                const key = `${i}-${j}`;
                presharedKeys[key] = await crypto.generatePresharedKey(seed);
            }
        }

        // Generate configurations for each peer
        const meshConfigs = peers.map((peer, index) => ({
            name: peer.name,
            config: generateMeshPeerConfig(peer, peers, index, cidr, dns, presharedKeys)
        }));

        // Store configurations
        currentMeshConfigs = meshConfigs;

        // Display configurations
        displayMeshConfigurations();

        // Restore button
        generateBtn.textContent = originalText;
        generateBtn.disabled = false;

    } catch (error) {
        // Restore button on error
        const generateBtn = document.querySelector('button[onclick="generateMeshConfigs()"]');
        if (generateBtn) {
            generateBtn.textContent = 'Generate Mesh Configurations';
            generateBtn.disabled = false;
        }
        alert('Error generating mesh configurations: ' + error.message);
    }
}

function validateMeshInputs(networkCIDR, peerCount) {
    // Validate network CIDR
    const cidrRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/([1-2]?[0-9]|3[0-2])$/;
    if (!cidrRegex.test(networkCIDR)) {
        alert('Invalid network CIDR format');
        return false;
    }

    // Validate peer count
    if (peerCount < 2 || peerCount > 20) {
        alert('Number of peers must be between 2 and 20');
        return false;
    }

    return true;
}

function generateMeshPeerConfig(currentPeer, allPeers, currentIndex, cidr, dns, presharedKeys) {
    let config = `# ${currentPeer.name} Configuration (Mesh Network)
[Interface]
PrivateKey = ${currentPeer.privateKey}
Address = ${currentPeer.ip}/${cidr}`;

    // Only add DNS if it's not empty
    if (dns && dns.trim()) {
        config += `
DNS = ${dns.trim()}`;
    }

    config += `
ListenPort = ${currentPeer.port}

`;

    // Add all other peers as peers
    allPeers.forEach((peer, peerIndex) => {
        if (peerIndex !== currentIndex) {
            // Get preshared key for this pair
            const minIndex = Math.min(currentIndex, peerIndex);
            const maxIndex = Math.max(currentIndex, peerIndex);
            const presharedKey = presharedKeys[`${minIndex}-${maxIndex}`];

            config += `# ${peer.name}
[Peer]
PublicKey = ${peer.publicKey}
PresharedKey = ${presharedKey}
AllowedIPs = ${peer.ip}/32`;

            // Add endpoint if available
            if (peer.endpoint) {
                config += `
Endpoint = ${peer.endpoint}:${peer.port}`;
            }

            config += `
PersistentKeepalive = 25

`;
        }
    });

    return config;
}

function displayMeshConfigurations() {
    const meshConfigs = document.getElementById('meshConfigs');
    meshConfigs.innerHTML = '';
    
    currentMeshConfigs.forEach((peerConfig, index) => {
        const configItem = document.createElement('div');
        configItem.className = 'client-config-item';
        configItem.innerHTML = `
            <div class="client-config-title">${peerConfig.name}</div>
            <div class="config-content">${peerConfig.config}</div>
            <button class="download-btn" onclick="downloadConfig('${peerConfig.name}', \`${peerConfig.config.replace(/`/g, '\\`')}\`)">
                Download ${peerConfig.name} Config
            </button>
        `;
        meshConfigs.appendChild(configItem);
    });
    
    document.getElementById('configOutput').style.display = 'block';
}