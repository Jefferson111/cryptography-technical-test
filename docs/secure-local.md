# Secure Local Connection with QKD

1. Preload some pre-determined keys in both QKD device and the gateway.

2. Connection should use symmetric encryption, and ideally Post-Quantum Secure.

3. Both parties will also pre-agree upon using the keys in a FIFO order and discard them everytime a QKD key is retrieved from the QKD device.

4. Everytime the gateway request a fresh pair of QKD key from the gateway, the same QKD key can be use to replenish the pre-determined keys that was discarded.

---

Processs is as depicted below:

1. Pre-load

```
+-+-+-+-+-+-+-+-+ 
! IPsec Gateway ! (Pre-load 10 Keys)
+-+-+-+-+-+-+-+-+
        | (encrypted communication with Key 1)
+-+-+-+-+-+-+-+-+ 
!   QKD Device  ! (Pre-load 10 Keys)
+-+-+-+-+-+-+-+-+

```

2. Request
```
+-+-+-+-+-+-+-+-+ 
! IPsec Gateway !
+-+-+-+-+-+-+-+-+
        | (Request QKD key, encrypted with Key 1)
+-+-+-+-+-+-+-+-+ 
!   QKD Device  !
+-+-+-+-+-+-+-+-+

```

3. Acknowledge
```
+-+-+-+-+-+-+-+-+ 
! IPsec Gateway !
+-+-+-+-+-+-+-+-+
        | (Ack QKD key, encrypted with Key 1)
+-+-+-+-+-+-+-+-+ 
!   QKD Device  !
+-+-+-+-+-+-+-+-+

```

4. Rotate keys
```
+-+-+-+-+-+-+-+-+ 
! IPsec Gateway ! (Discard Key 1, switch to Key 2)
+-+-+-+-+-+-+-+-+
        | 
+-+-+-+-+-+-+-+-+ 
!   QKD Device  ! (Discard Key 1, switch to Key 2)
+-+-+-+-+-+-+-+-+

```

5. Top-up (Assuminig QKD key size is same as Key size, if not use some Sponge function)
```
+-+-+-+-+-+-+-+-+ 
! IPsec Gateway ! (Top-up Key 11 using QKD key)
+-+-+-+-+-+-+-+-+
        | 
+-+-+-+-+-+-+-+-+ 
!   QKD Device  ! (Top-up Key 11 using QKD key)
+-+-+-+-+-+-+-+-+

```

---