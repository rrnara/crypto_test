import React, { useEffect, useState } from 'react';
import * as CryptoJS from 'crypto-js';
import { secretbox, randomBytes } from 'tweetnacl';
import { decodeUTF8 } from 'tweetnacl-util';
import * as bs58 from 'bs58';
import './App.css';
import { isEmpty } from 'lodash';

/* Converts a cryptjs WordArray to native Uint8Array */                                                                                  
function CryptJsWordArrayToUint8Array(wordArray) {                                                                                       
  const l = wordArray.sigBytes;                                                                                                        
  const words = wordArray.words;                                                                                                       
  const result = new Uint8Array(l);                                                                                                    
  let i = 0 /*dst*/, j = 0 /*src*/;
  while(true) {
      // here i is a multiple of 4
      if (i === l)
          break;
      let w = words[j++];
      result[i++] = (w & 0xff000000) >>> 24;
      if (i === l)
          break;
      result[i++] = (w & 0x00ff0000) >>> 16;                                                                                            
      if (i === l)                                                                                                                        
          break;                                                                                                                       
      result[i++] = (w & 0x0000ff00) >>> 8;
      if (i === l)
          break;
      result[i++] = (w & 0x000000ff);                                                                                                  
  }
  return result;
}
const iv = CryptoJS.enc.Utf8.parse(''); // CryptoJS.MD5('abcd');
const nonce = decodeUTF8('abcdabcdabcdabcdabcdabcd');

function customNacl(value, key) {
  const valArray = decodeUTF8(value)
  const keyArray = decodeUTF8(key)
  const box = secretbox(valArray, nonce, keyArray);
  return bs58.encode(box)
}

const HASH_ALGORITHMS = {
  MD5: CryptoJS.MD5,
  SHA256: CryptoJS.SHA256,
  SHA224: CryptoJS.SHA224,
  SHA511: CryptoJS.SHA512,
  SHA384: CryptoJS.SHA384,
  SHA3: CryptoJS.SHA3,
  RipeMD160: CryptoJS.RIPEMD160
}

const CRYPTO_ALGORITHMS = {
  AES: CryptoJS.AES.encrypt,
  TripleDES: CryptoJS.TripleDES.encrypt,
  RC4: CryptoJS.RC4.encrypt,
  Rabbit: CryptoJS.Rabbit.encrypt,
  TweetNaCl: customNacl
}

// CryptoJS.algo.AES.create()

function App() {
  const [algoType, setAlgoType] = useState('hash')
  const [selectedAlgo, setSelectedAlgo] = useState('')
  const [value, setValue] = useState('')
  const [key, setKey] = useState('')
  const [result, setResult] = useState('')

  const onChangeValue = (event) => {
    setAlgoType(event.target.value)
  }

  const isEncryption = algoType === 'encryption'
  const algoList = isEncryption ? CRYPTO_ALGORITHMS : HASH_ALGORITHMS
  const algoNameList = Object.keys(algoList)

  const onCalculate = () => {
    const algo = algoList[selectedAlgo]
    if (isEncryption) {
      const newResult = selectedAlgo === 'TweetNaCl' ? algo(value, CryptoJS.MD5(key).toString()) : bs58.encode(CryptJsWordArrayToUint8Array(algo(value, CryptoJS.MD5(key), { iv }).ciphertext))
      setResult(newResult)
    } else {
      const newResult = bs58.encode(CryptJsWordArrayToUint8Array(algo(value)))
      setResult(newResult)
    }
  }

  useEffect(() => {
    setSelectedAlgo(algoNameList[0])
  }, [isEncryption])

  return (
    <div className="App">
      <header className="App-header">
        <p>
          Crypto Testing
        </p>
        <div className="App-row" onChange={onChangeValue}>
          <input type="radio" defaultChecked value="hash" name="algo_type" /> Hash
          <input type="radio" value="encryption" name="algo_type" /> Encryption
        </div>
        <div className="App-row">
          <select name="algolist" value={selectedAlgo} onChange={(e) => setSelectedAlgo(e.target.value)}>
            {algoNameList.map((name) => (
              <option key={`algo_${name}`} value={name}>{name}</option>
            ))}
          </select>
        </div>
        <div className="App-row">
          Value: <input type="text" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        {isEncryption && (
          <div className="App-row">
            Key: <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
        )}
        <div className="App-row">
          <button type="button" disabled={isEmpty(value) && (isEncryption ? isEmpty(key) : false)} onClick={onCalculate}>Calculate</button>
        </div>
        <div className="App-row">
          {result}
        </div>
      </header>
    </div>
  );
}

export default App;
