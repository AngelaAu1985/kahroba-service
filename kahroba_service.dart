// kahroba_app.dart
// Advanced Dart package for simulating Kahroba smart payment system
// Goal: Provide modular business logic with multi-card support, transaction history, OTP, dynamic limits, and advanced security layers.

import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart'; // Added for secure hashing simulation
import 'package:zarinpal/zarinpal.dart';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:in_app_purchase/in_app_purchase.dart'; // Added for in-app purchases

// -----------------------------------------------------------------------------
// 1. Exceptions
// -----------------------------------------------------------------------------

class RegistrationError implements Exception {
  final String message;
  RegistrationError(this.message);

  @override
  String toString() => 'RegistrationError: $message';
}

class TransactionError implements Exception {
  final String message;
  TransactionError(this.message);

  @override
  String toString() => 'TransactionError: $message';
}

class InAppPurchaseError implements Exception {
  final String message;
  InAppPurchaseError(this.message);

  @override
  String toString() => 'InAppPurchaseError: $message';
}

// -----------------------------------------------------------------------------
// 2. Security Utilities
// -----------------------------------------------------------------------------

class DataProtector {
  static const String _encryptionKey = 'SecureKeyForKahroba2025!';

  static String encrypt(String data) {
    if (data.isEmpty) return '';
    final keyBytes = utf8.encode(_encryptionKey);
    final dataBytes = utf8.encode(data);
    final encryptedBytes = List<int>.generate(dataBytes.length, (i) {
      return dataBytes[i] ^ keyBytes[i % keyBytes.length];
    });
    return base64Encode(encryptedBytes);
  }

  static String decrypt(String encryptedData) {
    if (encryptedData.isEmpty) return '';
    try {
      final decodedBytes = base64Decode(encryptedData); // Fixed: Specific exception handling
      final keyBytes = utf8.encode(_encryptionKey);
      final decryptedBytes = List<int>.generate(decodedBytes.length, (i) {
        return decodedBytes[i] ^ keyBytes[i % keyBytes.length];
      });
      return utf8.decode(decryptedBytes);
    } on FormatException {
      throw RegistrationError('Invalid base64 encoded card data.');
    } catch (e) {
      throw RegistrationError('Failed to decrypt card data: ${e.toString()}');
    }
  }
}

// -----------------------------------------------------------------------------
// 3. Data Models & Enums
// -----------------------------------------------------------------------------

enum TransactionStatus {
  success,
  failure,
  insufficientFunds,
  requiresPin,
  nfcError,
  defaultCardNotSet,
  policyViolation,
  sessionExpired,
  cardExpired,
}

enum AuthPolicy {
  standard,
  mandatoryPin,
  biometricRequired,
  dynamicMFA,
}

class TransactionContext {
  final String merchantId;
  final String locationGeoHash;

  TransactionContext({required this.merchantId, required this.locationGeoHash});
}

class TransactionResult {
  final TransactionStatus status;
  final String message;
  final double amount;

  TransactionResult({required this.status, required this.message, required this.amount});
}

class PaymentToken {
  final String encryptedCardData;
  final String cardId;
  final DateTime expirationTime;
  final String signature;

  PaymentToken({
    required this.encryptedCardData,
    required this.cardId,
    required this.expirationTime,
    required this.signature,
  });

  bool isValid() => DateTime.now().isBefore(expirationTime);
}

class UserSession {
  final String sessionId;
  final DateTime loginTime;
  DateTime lastActivityTime;
  static const Duration sessionTimeout = Duration(minutes: 30);

  UserSession({required this.sessionId})
      : loginTime = DateTime.now(),
        lastActivityTime = DateTime.now();

  bool isExpired() => DateTime.now().difference(lastActivityTime) > sessionTimeout;

  void updateActivity() {
    lastActivityTime = DateTime.now();
  }
}

class UserIdentity {
  final String mobileNumber;
  final String nationalId;
  final String primaryPasswordHash;
  final List<BankCard> registeredCards;
  String defaultCardId;

  UserIdentity({
    required this.mobileNumber,
    required this.nationalId,
    required this.primaryPasswordHash,
    required this.registeredCards,
    required this.defaultCardId,
  });
}

class BankCard {
  final String cardId;
  final String cardAlias;
  final String encryptedCardNumber;
  final String encryptedCvv2;
  final String expiryDate;
  final String nationalIdOwner;
  double dailyLimit;
  AuthPolicy authPolicy;

  BankCard._internal({
    required this.cardId,
    required this.cardAlias,
    required this.encryptedCardNumber,
    required this.encryptedCvv2,
    required this.expiryDate,
    required this.nationalIdOwner,
    this.dailyLimit = 5000.0,
    this.authPolicy = AuthPolicy.standard,
  });

  factory BankCard({
    required String cardId,
    required String cardAlias,
    required String cardNumber,
    required String cvv2,
    required String expiryDate,
    required String nationalIdOwner,
    double dailyLimit = 5000.0,
    AuthPolicy authPolicy = AuthPolicy.standard,
  }) {
    if (cardNumber.length != 16 || !RegExp(r'^\d{16}$').hasMatch(cardNumber)) {
      throw RegistrationError('Invalid card number format.');
    }
    if (cvv2.length != 3 || !RegExp(r'^\d{3}$').hasMatch(cvv2)) {
      throw RegistrationError('Invalid CVV format.');
    }
    if (!RegExp(r'^\d{2}/\d{2}$').hasMatch(expiryDate)) {
      throw RegistrationError('Invalid expiry date format (MM/YY).');
    }
    return BankCard._internal(
      cardId: cardId,
      cardAlias: cardAlias,
      encryptedCardNumber: DataProtector.encrypt(cardNumber),
      encryptedCvv2: DataProtector.encrypt(cvv2),
      expiryDate: expiryDate,
      nationalIdOwner: nationalIdOwner,
      dailyLimit: dailyLimit,
      authPolicy: authPolicy,
    );
  }

  bool isExpired() {
    final parts = expiryDate.split('/');
    final month = int.parse(parts[0]);
    final year = int.parse(parts[1]) + 2000;
    final expiry = DateTime(year, month + 1, 1);
    return DateTime.now().isAfter(expiry);
  }

  String get unencryptedCardNumber => DataProtector.decrypt(encryptedCardNumber);

  String get maskedCardNumber {
    final rawNumber = unencryptedCardNumber;
    return '**** **** **** ${rawNumber.substring(rawNumber.length - 4)}';
  }

  Map<String, dynamic> toJson() => {
        'cardId': cardId,
        'cardAlias': cardAlias,
        'encryptedCardNumber': encryptedCardNumber,
        'encryptedCvv2': encryptedCvv2,
        'expiryDate': expiryDate,
        'nationalIdOwner': nationalIdOwner,
        'dailyLimit': dailyLimit,
        'authPolicy': authPolicy.name,
      };

  factory BankCard.fromJson(Map<String, dynamic> json) => BankCard._internal(
        cardId: json['cardId'] as String,
        cardAlias: json['cardAlias'] as String,
        encryptedCardNumber: json['encryptedCardNumber'] as String,
        encryptedCvv2: json['encryptedCvv2'] as String,
        expiryDate: json['expiryDate'] as String,
        nationalIdOwner: json['nationalIdOwner'] as String,
        dailyLimit: json['dailyLimit'] as double,
        authPolicy: AuthPolicy.values.firstWhere(
            (e) => e.name == json['authPolicy'] as String,
            orElse: () => AuthPolicy.standard),
      );
}

class KahrobaTransaction {
  final DateTime timestamp;
  final double amount;
  final TransactionStatus status;
  final String cardId;
  final String message;
  final double feeAmount;
  final String? securityFlag;
  final String locationGeoHash;
  final int riskScore;

  KahrobaTransaction({
    required this.timestamp,
    required this.amount,
    required this.status,
    required this.cardId,
    required this.message,
    required this.feeAmount,
    required this.locationGeoHash,
    required this.riskScore,
    this.securityFlag,
  });

  Map<String, dynamic> toJson() => {
        'timestamp': timestamp.toIso8601String(),
        'amount': amount,
        'status': status.name,
        'cardId': cardId,
        'message': message,
        'feeAmount': feeAmount,
        'securityFlag': securityFlag,
        'locationGeoHash': locationGeoHash,
        'riskScore': riskScore,
      };

  factory KahrobaTransaction.fromJson(Map<String, dynamic> json) =>
      KahrobaTransaction(
        timestamp: DateTime.parse(json['timestamp'] as String),
        amount: json['amount'] as double,
        status: TransactionStatus.values.firstWhere(
            (e) => e.name == json['status'] as String,
            orElse: () => TransactionStatus.failure),
        cardId: json['cardId'] as String,
        message: json['message'] as String,
        feeAmount: json['feeAmount'] as double,
        securityFlag: json['securityFlag'] as String?,
        locationGeoHash: json['locationGeoHash'] as String,
        riskScore: json['riskScore'] as int,
      );
}

// -----------------------------------------------------------------------------
// 4. NFC Hardware Interface
// -----------------------------------------------------------------------------

abstract class NfcDeviceInterface {
  Future<TransactionResult> transmitPaymentData({
    required PaymentToken token,
    required double transactionAmount,
    String? pin,
  });

  Future<double> getBalance({
    required String cardId,
  });

  Future<TransactionResult> topUpBalance({
    required PaymentToken token,
    required double amount,
    String? pin,
  });
}

class NfcSimulator implements NfcDeviceInterface {
  static const double pinRequiredThreshold = 70.0;

  final Map<String, double> _mockBalances = {
    'card1': 1500.0,
    'card2': 50.0,
  };

  final Map<String, String> _mockPins = {
    'card1': '1111',
    'card2': '2222',
  };

  void initializeCardBalance(String cardId) {
    // Fixed: Initialize balance for new cards
    if (!_mockBalances.containsKey(cardId)) {
      _mockBalances[cardId] = 0.0;
    }
  }

  @override
  Future<TransactionResult> transmitPaymentData({
    required PaymentToken token,
    required double transactionAmount,
    String? pin,
  }) async {
    await Future.delayed(const Duration(milliseconds: 500));

    if (!token.isValid()) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Payment token expired. Please try again.',
        amount: transactionAmount,
      );
    }

    if (token.signature != 'SIMULATED_SIGNATURE_${token.cardId}') {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Invalid token signature.',
        amount: transactionAmount,
      );
    }

    final decryptedData = DataProtector.decrypt(token.encryptedCardData);
    final cardDetails = jsonDecode(decryptedData);

    final cardId = token.cardId;
    final decryptedCardNumber = cardDetails['cardNumber'];
    final decryptedCvv2 = cardDetails['cvv2'];

    final currentBalance = _mockBalances[cardId] ?? 0.0;

    if (transactionAmount > pinRequiredThreshold && pin == null) {
      return TransactionResult(
        status: TransactionStatus.requiresPin,
        message: 'PIN required for transactions above ${pinRequiredThreshold.toStringAsFixed(2)}.',
        amount: transactionAmount,
      );
    }

    if (pin != null && pin != _mockPins[cardId]) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Incorrect PIN. Please try again.',
        amount: transactionAmount,
      );
    }

    if (transactionAmount > currentBalance) {
      return TransactionResult(
        status: TransactionStatus.insufficientFunds,
        message: 'Insufficient balance (${currentBalance.toStringAsFixed(2)}).',
        amount: transactionAmount,
      );
    }

    _mockBalances[cardId] = currentBalance - transactionAmount;
    final newBalance = _mockBalances[cardId];
    return TransactionResult(
      status: TransactionStatus.success,
      message:
          'Payment successful. (Card: ****${decryptedCardNumber.substring(decryptedCardNumber.length - 4)}) Balance: ${newBalance!.toStringAsFixed(2)}',
      amount: transactionAmount,
    );
  }

  @override
  Future<double> getBalance({
    required String cardId,
  }) async {
    await Future.delayed(const Duration(milliseconds: 200));
    return _mockBalances[cardId] ?? 0.0;
  }

  @override
  Future<TransactionResult> topUpBalance({
    required PaymentToken token,
    required double amount,
    String? pin,
  }) async {
    await Future.delayed(const Duration(milliseconds: 500));

    if (!token.isValid()) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Payment token expired. Please try again.',
        amount: amount,
      );
    }

    if (token.signature != 'SIMULATED_SIGNATURE_${token.cardId}') {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Invalid token signature.',
        amount: amount,
      );
    }

    final decryptedData = DataProtector.decrypt(token.encryptedCardData);
    final cardDetails = jsonDecode(decryptedData);

    final cardId = token.cardId;
    final decryptedCardNumber = cardDetails['cardNumber'];

    if (amount <= 0) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Top-up amount must be positive.',
        amount: amount,
      );
    }

    if (pin != null && pin != _mockPins[cardId]) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Incorrect PIN. Please try again.',
        amount: amount,
      );
    }

    final currentBalance = _mockBalances[cardId] ?? 0.0;
    _mockBalances[cardId] = currentBalance + amount;
    final newBalance = _mockBalances[cardId];
    return TransactionResult(
      status: TransactionStatus.success,
      message:
          'Top-up successful. (Card: ****${decryptedCardNumber.substring(decryptedCardNumber.length - 4)}) New Balance: ${newBalance!.toStringAsFixed(2)}',
      amount: amount,
    );
  }
}

// -----------------------------------------------------------------------------
// 6. Fraud Detection Module (for modularity)
// -----------------------------------------------------------------------------

class FraudDetection {
  final int fraudVelocityMinutes;
  final int highRiskScoreThreshold;

  FraudDetection({
    this.fraudVelocityMinutes = 10,
    this.highRiskScoreThreshold = 70,
  });

  int calculateRiskScore({
    required double amount,
    required String currentGeoHash,
    String? lastGeoHash,
    required DateTime lastTransactionTime,
    required Map<String, int> securityIncidentCount,
    required String userId,
  }) {
    int score = 0;
    if (amount > 500.0) score += 30;
    if (amount > 1500.0) score += 40;
    if (lastGeoHash != null &&
        lastGeoHash != currentGeoHash &&
        DateTime.now().difference(lastTransactionTime).inMinutes < fraudVelocityMinutes) {
      score += 50;
    }
    score += (securityIncidentCount[userId] ?? 0) * 10;
    return score;
  }
}

// -----------------------------------------------------------------------------
// 7. OTP Service Module (for modularity)
// -----------------------------------------------------------------------------

class OtpService {
  final Map<String, OtpEntry> _otpStore = {};
  final Map<String, int> _otpAttempts = {};
  static const int _maxOtpAttempts = 3;
  final Random _random = Random();

  class OtpEntry {
    final String code;
    final DateTime expiryTime;

    OtpEntry(this.code, {required this.expiryTime});
  }

  String generateVerificationCode(String mobileNumber) {
    final code = (_random.nextInt(899999) + 100000).toString();
    _otpStore[mobileNumber] = OtpEntry(
      code,
      expiryTime: DateTime.now().add(Duration(minutes: 5)),
    );
    _otpAttempts[mobileNumber] = 0;
    return code;
  }

  bool validateVerificationCode(String mobileNumber, String code) {
    final attempts = _otpAttempts[mobileNumber] ?? 0;
    if (attempts >= _maxOtpAttempts) {
      _otpStore.remove(mobileNumber);
      throw RegistrationError('Too many OTP attempts. Please request a new OTP.');
    }

    final otpEntry = _otpStore[mobileNumber];
    if (otpEntry == null || DateTime.now().isAfter(otpEntry.expiryTime)) {
      _otpAttempts[mobileNumber] = attempts + 1;
      return false;
    }
    if (otpEntry.code != code) {
      _otpAttempts[mobileNumber] = attempts + 1;
      return false;
    }
    _otpStore.remove(mobileNumber);
    _otpAttempts.remove(mobileNumber);
    return true;
  }
}

// -----------------------------------------------------------------------------
// 8. Payment Gateway Interface (for modularity)
// -----------------------------------------------------------------------------

abstract class PaymentGatewayInterface {
  Future<String> initiateOnlinePayment({
    required double amount,
    required String description,
    required String callbackUrl,
  });

  Future<TransactionResult> verifyOnlinePayment({
    required String status,
    required String authority,
    required double amount,
  });
}

class ZarinpalGateway implements PaymentGatewayInterface {
  final String merchantId;
  final bool isSandbox;
  final PaymentRequest _paymentRequest;

  ZarinpalGateway({
    required this.merchantId,
    this.isSandbox = true,
    required String callbackUrl,
  }) : _paymentRequest = PaymentRequest()
          ..setIsSandBox(isSandbox)
          ..setMerchantID(merchantId)
          ..setCallbackURL(callbackUrl);

  @override
  Future<String> initiateOnlinePayment({
    required double amount,
    required String description,
    required String callbackUrl,
  }) async {
    _paymentRequest.setAmount((amount * 100).toInt()); // Fixed: Handle decimals
    _paymentRequest.setDescription(description);

    final completer = Completer<String>();
    ZarinPal().startPayment(_paymentRequest, (int? status, String? paymentGatewayUri) {
      if (status == 100 && paymentGatewayUri != null) {
        completer.complete(paymentGatewayUri);
      } else {
        completer.completeError(TransactionError('Failed to initiate Zarinpal payment: status $status'));
      }
    });

    return completer.future;
  }

  @override
  Future<TransactionResult> verifyOnlinePayment({
    required String status,
    required String authority,
    required double amount,
  }) async {
    final completer = Completer<TransactionResult>();
    ZarinPal().verificationPayment(status, authority, _paymentRequest, (bool isPaymentSuccess, String refID, PaymentRequest paymentRequest) {
      if (isPaymentSuccess) {
        completer.complete(TransactionResult(
          status: TransactionStatus.success,
          message: 'Online payment verified. Ref ID: $refID',
          amount: amount,
        ));
      } else {
        completer.complete(TransactionResult(
          status: TransactionStatus.failure,
          message: 'Online payment verification failed.',
          amount: amount,
        ));
      }
    });

    return completer.future;
  }
}

// -----------------------------------------------------------------------------
// 9. In-App Purchase Interface
// -----------------------------------------------------------------------------

abstract class InAppPurchaseInterface {
  Future<List<ProductDetails>> fetchProducts(List<String> productIds);
  Future<TransactionResult> purchaseProduct(String productId, String cardId);
  Future<bool> verifyPurchase(PurchaseDetails purchase);
}

class KahrobaInAppPurchase implements InAppPurchaseInterface {
  final InAppPurchase _inAppPurchase = InAppPurchase.instance;
  final KahrobaService _kahrobaService;

  KahrobaInAppPurchase(this._kahrobaService);

  @override
  Future<List<ProductDetails>> fetchProducts(List<String> productIds) async {
    final bool isAvailable = await _inAppPurchase.isAvailable();
    if (!isAvailable) {
      throw InAppPurchaseError('In-app purchase is not available.');
    }

    final ProductDetailsResponse response = await _inAppPurchase.queryProductDetails(productIds.toSet());
    if (response.notFoundIDs.isNotEmpty) {
      throw InAppPurchaseError('Some products were not found: ${response.notFoundIDs.join(", ")}');
    }
    return response.productDetails;
  }

  @override
  Future<TransactionResult> purchaseProduct(String productId, String cardId) async {
    try {
      final bool isAvailable = await _inAppPurchase.isAvailable();
      if (!isAvailable) {
        return TransactionResult(
          status: TransactionStatus.failure,
          message: 'In-app purchase is not available.',
          amount: 0.0,
        );
      }

      final ProductDetailsResponse response = await _inAppPurchase.queryProductDetails({productId});
      if (response.productDetails.isEmpty) {
        return TransactionResult(
          status: TransactionStatus.failure,
          message: 'Product not found.',
          amount: 0.0,
        );
      }

      final ProductDetails product = response.productDetails.first;
      final PurchaseParam purchaseParam = PurchaseParam(productDetails: product);
      await _inAppPurchase.buyConsumable(purchaseParam: purchaseParam);

      return TransactionResult(
        status: TransactionStatus.success,
        message: 'Purchase initiated for ${product.title}. Please complete the payment.',
        amount: double.parse(product.price.replaceAll(RegExp(r'[^\d.]'), '')),
      );
    } catch (e) {
      return TransactionResult(
        status: TransactionStatus.failure,
        message: 'Purchase failed: ${e.toString()}',
        amount: 0.0,
      );
    }
  }

  @override
  Future<bool> verifyPurchase(PurchaseDetails purchase) async {
    if (purchase.status == PurchaseStatus.purchased || purchase.status == PurchaseStatus.restored) {
      if (purchase.pendingCompletePurchase) {
        await _inAppPurchase.completePurchase(purchase);
      }
      return true;
    }
    return false;
  }
}

// -----------------------------------------------------------------------------
// 5. Kahroba Service
// -----------------------------------------------------------------------------

class KahrobaService {
  UserIdentity? _currentUser;
  UserSession? _currentSession;
  final NfcDeviceInterface _nfcDevice;
  final Map<String, UserIdentity> _userDatabase = {};
  final List<KahrobaTransaction> _transactionLog = [];
  final OtpService _otpService = OtpService();
  final Map<String, double> _dailySpending = {};
  DateTime _lastTransactionDate = DateTime.now();
  DateTime _lastTransactionTime = DateTime.fromMicrosecondsSinceEpoch(0);
  String? _lastTransactionGeoHash;
  static const Duration _cooldownPeriod = Duration(seconds: 5);
  final Map<String, int> _securityIncidentCount = {};
  final FraudDetection _fraudDetection = FraudDetection();
  PaymentGatewayInterface? _paymentGateway;
  InAppPurchaseInterface? _inAppPurchase;

  KahrobaService({
    NfcDeviceInterface? nfcDevice,
    PaymentGatewayInterface? paymentGateway,
    InAppPurchaseInterface? inAppPurchase,
  })  : _nfcDevice = nfcDevice ?? NfcSimulator(),
        _paymentGateway = paymentGateway,
        _inAppPurchase = inAppPurchase;

  String requestOtpForUser() {
    _checkSession();


    return _otpService.generateVerificationCode(_currentUser!.mobileNumber);
  }

  void _checkSession() {
    if (_currentSession == null || _currentUser == null) {
      throw TransactionError('Please log in first.');
    }
    if (_currentSession!.isExpired()) {
      _currentSession = null;
      _currentUser = null;
      throw TransactionError('Session expired. Please log in again.');
    }
    _currentSession!.updateActivity();
  }

  void _logTransaction({
    required double amount,
    required TransactionStatus status,
    required String cardId,
    required String message,
    required double feeAmount,
    required String locationGeoHash,
    required int riskScore,
    String? securityFlag,
  }) {
    _transactionLog.add(KahrobaTransaction(
      timestamp: DateTime.now(),
      amount: amount,
      status: status,
      cardId: cardId,
      message: message,
      feeAmount: feeAmount,
      securityFlag: securityFlag,
      locationGeoHash: locationGeoHash,
      riskScore: riskScore,
    ));

    if (status != TransactionStatus.success && riskScore > 50) {
      final userId = _currentUser?.mobileNumber ?? 'unknown';
      _securityIncidentCount[userId] = (_securityIncidentCount[userId] ?? 0) + 1;
    }
  }

  int _calculateRiskScore(double amount, String currentGeoHash) {
    final userId = _currentUser?.mobileNumber ?? 'unknown';
    return _fraudDetection.calculateRiskScore(
      amount: amount,
      currentGeoHash: currentGeoHash,
      lastGeoHash: _lastTransactionGeoHash,
      lastTransactionTime: _lastTransactionTime,
      securityIncidentCount: _securityIncidentCount,
      userId: userId,
    );
  }

  double get todaySpent {
    if (_currentUser == null) return 0.0;
    final today = DateTime.now();
    if (_lastTransactionDate.day != today.day) {
      _dailySpending.clear();
      _lastTransactionDate = today;
    }
    return _dailySpending[_currentUser!.defaultCardId] ?? 0.0;
  }

  Future<void> registerUser({
    required String mobileNumber,
    required String nationalId,
    required String primaryPassword,
    required BankCard initialCard,
  }) async {
    if (!RegExp(r'^09\d{9}$').hasMatch(mobileNumber)) {
      throw RegistrationError('Invalid mobile number format.');
    }
    if (nationalId.length != 10 || !RegExp(r'^\d{10}$').hasMatch(nationalId)) {
      throw RegistrationError('Invalid national ID.');
    }
    if (nationalId != initialCard.nationalIdOwner) {
      throw RegistrationError('Card does not match national ID.');
    }
    // Fixed: Use a safer hash simulation
    final passwordHash = base64Encode(sha256.convert(utf8.encode(primaryPassword)).bytes);
    final newUser = UserIdentity(
      mobileNumber: mobileNumber,
      nationalId: nationalId,
      primaryPasswordHash: passwordHash,
      registeredCards: [initialCard],
      defaultCardId: initialCard.cardId,
    );
    _userDatabase[mobileNumber] = newUser;
    _currentUser = newUser;
    _currentSession = UserSession(sessionId: mobileNumber);
    if (_nfcDevice is NfcSimulator) {
      (_nfcDevice as NfcSimulator).initializeCardBalance(initialCard.cardId);
    }
  }

  void setDefaultCard(String cardId, String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    if (_currentUser!.registeredCards.any((c) => c.cardId == cardId)) {
      _currentUser!.defaultCardId = cardId;
    } else {
      throw RegistrationError('Card not found.');
    }
  }

  void updateCardPolicy(String cardId, AuthPolicy newPolicy, String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw RegistrationError('Card not found.'),
    );
    card.authPolicy = newPolicy;
  }

  Future<TransactionResult> processPayment({
    required double amount,
    required TransactionContext context,
    String? pin,
    bool isBiometricAuthenticated = false,
  }) async {
    _checkSession();

    if (DateTime.now().difference(_lastTransactionTime) < _cooldownPeriod) {
      throw TransactionError('Please wait a few seconds and try again.');
    }

    final defaultCard = _currentUser!.registeredCards.firstWhere(
      (card) => card.cardId == _currentUser!.defaultCardId,
      orElse: () => throw TransactionError('Default card not selected.'),
    );

    if (defaultCard.isExpired()) {
      return TransactionResult(
        status: TransactionStatus.cardExpired,
        message: 'Card has expired. Please use a valid card.',
        amount: amount,
      );
    }

    if (todaySpent + amount > defaultCard.dailyLimit) {
      return TransactionResult(
        status: TransactionStatus.policyViolation,
        message: 'Transaction exceeds daily limit (${defaultCard.dailyLimit}).',
        amount: amount,
      );
    }

    final riskScore = _calculateRiskScore(amount, context.locationGeoHash);
    String? securityFlag;

    if (riskScore >= _fraudDetection.highRiskScoreThreshold) {
      securityFlag = 'DRS_HIGH_RISK_FORCED_MFA';
      defaultCard.authPolicy = AuthPolicy.dynamicMFA;
    } else if (_lastTransactionGeoHash != null &&
        _lastTransactionGeoHash != context.locationGeoHash &&
        DateTime.now().difference(_lastTransactionTime).inMinutes < _fraudDetection.fraudVelocityMinutes) {
      securityFlag = 'VELOCITY_FRAUD_RISK_HIGH';
    } else if (defaultCard.authPolicy == AuthPolicy.dynamicMFA) {
      defaultCard.authPolicy = AuthPolicy.standard;
    }

    if ((defaultCard.authPolicy == AuthPolicy.mandatoryPin || defaultCard.authPolicy == AuthPolicy.dynamicMFA) && pin == null) {
      return TransactionResult(
        status: TransactionStatus.requiresPin,
        message: 'Please enter card PIN.',
        amount: amount,
      );
    }
    if ((defaultCard.authPolicy == AuthPolicy.biometricRequired || defaultCard.authPolicy == AuthPolicy.dynamicMFA) &&
        !isBiometricAuthenticated) {
      return TransactionResult(
        status: TransactionStatus.policyViolation,
        message: 'Biometric authentication required.',
        amount: amount,
      );
    }

    final cardDataForToken = jsonEncode({
      'cardNumber': defaultCard.unencryptedCardNumber,
      'cvv2': DataProtector.decrypt(defaultCard.encryptedCvv2),
    });

    final paymentToken = PaymentToken(
      encryptedCardData: DataProtector.encrypt(cardDataForToken),
      cardId: defaultCard.cardId,
      expirationTime: DateTime.now().add(const Duration(minutes: 5)),
      signature: 'SIMULATED_SIGNATURE_${defaultCard.cardId}',
    );

    TransactionResult result;
    try {
      result = await _nfcDevice.transmitPaymentData(
        token: paymentToken,
        transactionAmount: amount,
        pin: pin,
      );

      double fee = 0.0;
      if (result.status == TransactionStatus.success) {
        const double serviceFeeRate = 0.01;
        fee = amount * serviceFeeRate;
        _dailySpending[defaultCard.cardId] = todaySpent + amount;
        _lastTransactionTime = DateTime.now();
        _lastTransactionGeoHash = context.locationGeoHash;

        if (amount > 1000.0) {
          securityFlag = securityFlag != null ? '$securityFlag, HIGH_VALUE_TRANSACTION' : 'HIGH_VALUE_TRANSACTION';
        }

        final netAmount = amount - fee;
        result = TransactionResult(
          status: TransactionStatus.success,
          message: 'Payment successful: ${netAmount.toStringAsFixed(2)} (Fee: ${fee.toStringAsFixed(2)})',
          amount: netAmount,
        );
      } else if (result.status == TransactionStatus.insufficientFunds) {
        securityFlag = securityFlag != null ? '$securityFlag, INSUFFICIENT_FUNDS' : 'INSUFFICIENT_FUNDS';
      }

      _logTransaction(
        amount: amount,
        status: result.status,
        cardId: defaultCard.cardId,
        message: result.message,
        feeAmount: fee,
        securityFlag: securityFlag,
        locationGeoHash: context.locationGeoHash,
        riskScore: riskScore,
      );

      return result;
    } on Exception catch (e) {
      _logTransaction(
        amount: amount,
        status: TransactionStatus.nfcError,
        cardId: defaultCard.cardId,
        message: 'NFC communication error: Please try again.',
        feeAmount: 0.0,
        securityFlag: 'NFC_COMMUNICATION_ERROR',
        locationGeoHash: context.locationGeoHash,
        riskScore: riskScore,
      );
      throw TransactionError('NFC communication error: Please try again.');
    }
  }

  bool login(String mobileNumber, String password) {
    if (!RegExp(r'^09\d{9}$').hasMatch(mobileNumber)) {
      throw RegistrationError('Invalid mobile number format.');
    }
    final user = _userDatabase[mobileNumber];
    if (user != null && user.primaryPasswordHash == base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      _currentUser = user;
      _currentSession = UserSession(sessionId: mobileNumber);
      _lastTransactionTime = DateTime.fromMicrosecondsSinceEpoch(0);
      return true;
    }
    return false;
  }

  void logout() {
    _checkSession();
    _currentUser = null;
    _currentSession = null;
  }

  List<KahrobaTransaction> getTransactionLog() {
    _checkSession();
    final userCardIds = _currentUser!.registeredCards.map((c) => c.cardId).toSet();
    return List<KahrobaTransaction>.from(_transactionLog
            .where((log) => userCardIds.contains(log.cardId))
            .toList())
        ..sort((a, b) => b.timestamp.compareTo(a.timestamp)); // Fixed: Return new sorted list
  }

  void addCard(BankCard newCard, String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    if (_currentUser!.nationalId != newCard.nationalIdOwner) {
      throw RegistrationError('Card does not match national ID.');
    }
    if (_currentUser!.registeredCards.any((c) => c.cardId == newCard.cardId)) {
      throw RegistrationError('Card already registered.');
    }
    _currentUser!.registeredCards.add(newCard);
    if (_nfcDevice is NfcSimulator) {
      (_nfcDevice as NfcSimulator).initializeCardBalance(newCard.cardId); // Fixed: Initialize balance
    }
  }

  void removeCard(String cardId, String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    final cardIndex = _currentUser!.registeredCards.indexWhere((c) => c.cardId == cardId);
    if (cardIndex == -1) {
      throw RegistrationError('Card not found.');
    }
    if (_currentUser!.defaultCardId == cardId) {
      throw RegistrationError('Cannot remove default card. Set another default first.');
    }
    _currentUser!.registeredCards.removeAt(cardIndex);
  }

  void updateDailyLimit(String cardId, double newLimit, String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    if (newLimit <= 0) {
      throw RegistrationError('Daily limit must be positive.');
    }
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw RegistrationError('Card not found.'),
    );
    card.dailyLimit = newLimit;
  }

  List<Map<String, dynamic>> getRegisteredCards() {
    _checkSession();
    return _currentUser!.registeredCards.map((card) => {
          'cardId': card.cardId,
          'cardAlias': card.cardAlias,
          'maskedCardNumber': card.maskedCardNumber,
          'expiryDate': card.expiryDate,
          'dailyLimit': card.dailyLimit,
          'authPolicy': card.authPolicy.name,
          'isDefault': card.cardId == _currentUser!.defaultCardId,
        }).toList();
  }

  void changePassword(String oldPassword, String newPassword, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(oldPassword)).bytes)) {
      throw RegistrationError('Invalid old password or OTP.');
    }
    _currentUser!.primaryPasswordHash = base64Encode(sha256.convert(utf8.encode(newPassword)).bytes);
  }

  bool isUserLocked() {
    _checkSession();
    final userId = _currentUser!.mobileNumber;
    final incidents = _securityIncidentCount[userId] ?? 0;
    return incidents >= 5;
  }

  Map<String, dynamic> exportUserDataToJson() {
    _checkSession();
    return {
      'mobileNumber': _currentUser!.mobileNumber,
      'nationalId': _currentUser!.nationalId,
      'primaryPasswordHash': _currentUser!.primaryPasswordHash,
      'registeredCards': _currentUser!.registeredCards.map((card) => card.toJson()).toList(),
      'defaultCardId': _currentUser!.defaultCardId,
    };
  }

  void importUserDataFromJson(Map<String, dynamic> json) {
    final mobileNumber = json['mobileNumber'] as String;
    final nationalId = json['nationalId'] as String;
    final primaryPasswordHash = json['primaryPasswordHash'] as String;
    final registeredCards = (json['registeredCards'] as List)
        .map((cardJson) => BankCard.fromJson(cardJson as Map<String, dynamic>))
        .toList();
    final defaultCardId = json['defaultCardId'] as String;

    // Fixed: Validate defaultCardId
    if (!registeredCards.any((card) => card.cardId == defaultCardId)) {
      throw RegistrationError('Default card ID does not exist in registered cards.');
    }

    final importedUser = UserIdentity(
      mobileNumber: mobileNumber,
      nationalId: nationalId,
      primaryPasswordHash: primaryPasswordHash,
      registeredCards: registeredCards,
      defaultCardId: defaultCardId,
    );
    _userDatabase[mobileNumber] = importedUser;
    if (_nfcDevice is NfcSimulator) {
      for (var card in registeredCards) {
        (_nfcDevice as NfcSimulator).initializeCardBalance(card.cardId);
      }
    }
  }

  Future<double> getCardBalance(String cardId) async {
    _checkSession();
    if (!_currentUser!.registeredCards.any((c) => c.cardId == cardId)) {
      throw TransactionError('Card not found.');
    }
    return _nfcDevice.getBalance(cardId: cardId);
  }

  String generateCardToken(String cardId) {
    _checkSession();
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw TransactionError('Card not found.'),
    );
    final cardData = jsonEncode({
      'cardNumber': card.unencryptedCardNumber,
      'cvv2': DataProtector.decrypt(card.encryptedCvv2),
      'expiryDate': card.expiryDate,
      'cardId': card.cardId,
    });
    final encryptedData = DataProtector.encrypt(cardData);
    return base64Encode(utf8.encode(encryptedData + '|SIMULATED_TOKEN_SIGNATURE'));
  }

  bool validateCardToken(String token) {
    try {
      final decoded = utf8.decode(base64Decode(token));
      final parts = decoded.split('|');
      if (parts.length != 2 || parts[1] != 'SIMULATED_TOKEN_SIGNATURE') {
        return false;
      }
      final decryptedData = DataProtector.decrypt(parts[0]);
      jsonDecode(decryptedData);
      return true;
    } catch (e) {
      return false;
    }
  }

  Future<TransactionResult> processTopUp({
    required double amount,
    required String cardId,
    String? pin,
  }) async {
    _checkSession();
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw TransactionError('Card not found.'),
    );

    if (card.isExpired()) {
      return TransactionResult(
        status: TransactionStatus.cardExpired,
        message: 'Card has expired. Please use a valid card.',
        amount: amount,
      );
    }

    final cardDataForToken = jsonEncode({
      'cardNumber': card.unencryptedCardNumber,
      'cvv2': DataProtector.decrypt(card.encryptedCvv2),
    });

    final paymentToken = PaymentToken(
      encryptedCardData: DataProtector.encrypt(cardDataForToken),
      cardId: card.cardId,
      expirationTime: DateTime.now().add(const Duration(minutes: 5)),
      signature: 'SIMULATED_SIGNATURE_${card.cardId}',
    );

    TransactionResult result;
    try {
      result = await _nfcDevice.topUpBalance(
        token: paymentToken,
        amount: amount,
        pin: pin,
      );

      if (result.status == TransactionStatus.success) {
        _logTransaction(
          amount: amount,
          status: result.status,
          cardId: card.cardId,
          message: result.message,
          feeAmount: 0.0,
          locationGeoHash: 'simulated',
          riskScore: 0,
          securityFlag: 'TOP_UP',
        );
      }

      return result;
    } on Exception catch (e) {
      throw TransactionError('Top-up error: Please try again.');
    }
  }

  List<KahrobaTransaction> searchTransactionsByDate(DateTime startDate, DateTime endDate) {
    _checkSession();
    final userCardIds = _currentUser!.registeredCards.map((c) => c.cardId).toSet();
    return List<KahrobaTransaction>.from(_transactionLog
            .where((log) =>
                userCardIds.contains(log.cardId) &&
                (log.timestamp.isAfter(startDate) || log.timestamp.isAtSameMomentAs(startDate)) &&
                (log.timestamp.isBefore(endDate) || log.timestamp.isAtSameMomentAs(endDate)))
            .toList())
        ..sort((a, b) => b.timestamp.compareTo(a.timestamp)); // Fixed: Inclusive date range
  }

  void clearSecurityIncidents(String password, String otpCode) {
    _checkSession();
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != base64Encode(sha256.convert(utf8.encode(password)).bytes)) {
      throw RegistrationError('Invalid password or OTP.');
    }
    final userId = _currentUser!.mobileNumber;
    _securityIncidentCount.remove(userId);
  }

  void setPaymentGateway(PaymentGatewayInterface gateway) {
    _paymentGateway = gateway;
  }

  Future<String> initiateOnlineTopUp({
    required double amount,
    required String cardId,
    required String callbackUrl,
    String description = 'Online top-up for Kahroba card',
  }) async {
    _checkSession();
    if (_paymentGateway == null) {
      throw TransactionError('No payment gateway configured.');
    }
    if (!_currentUser!.registeredCards.any((c) => c.cardId == cardId)) {
      throw TransactionError('Card not found.');
    }
    return _paymentGateway!.initiateOnlinePayment(
      amount: amount,
      description: description,
      callbackUrl: callbackUrl,
    );
  }

  Future<TransactionResult> verifyOnlineTopUp({
    required String status,
    required String authority,
    required double amount,
    required String cardId,
  }) async {
    _checkSession();
    if (_paymentGateway == null) {
      throw TransactionError('No payment gateway configured.');
    }
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw TransactionError('Card not found.'),
    );

    final result = await _paymentGateway!.verifyOnlinePayment(
      status: status,
      authority: authority,
      amount: amount,
    );

    if (result.status == TransactionStatus.success) {
      // Fixed: Update balance using topUpBalance
      final cardDataForToken = jsonEncode({
        'cardNumber': card.unencryptedCardNumber,
        'cvv2': DataProtector.decrypt(card.encryptedCvv2),
      });
      final paymentToken = PaymentToken(
        encryptedCardData: DataProtector.encrypt(cardDataForToken),
        cardId: card.cardId,
        expirationTime: DateTime.now().add(const Duration(minutes: 5)),
        signature: 'SIMULATED_SIGNATURE_${card.cardId}',
      );
      final topUpResult = await _nfcDevice.topUpBalance(
        token: paymentToken,
        amount: amount,
        pin: null, // Online top-up may not require PIN
      );

      if (topUpResult.status == TransactionStatus.success) {
        _logTransaction(
          amount: amount,
          status: topUpResult.status,
          cardId: cardId,
          message: '${result.message} New balance: ${topUpResult.message.split('New Balance: ').last}',
          feeAmount: 0.0,
          locationGeoHash: 'online',
          riskScore: 0,
          securityFlag: 'ONLINE_TOP_UP',
        );
        return topUpResult;
      } else {
        return topUpResult; // Return failure from topUpBalance if it fails
      }
    }
    return result;
  }

  void setInAppPurchase(InAppPurchaseInterface inAppPurchase) {
    _inAppPurchase = inAppPurchase;
  }

  Future<List<ProductDetails>> fetchInAppProducts(List<String> productIds) async {
    _checkSession();
    if (_inAppPurchase == null) {
      throw InAppPurchaseError('No in-app purchase service configured.');
    }
    return _inAppPurchase!.fetchProducts(productIds);
  }

  Future<TransactionResult> processInAppPurchase({
    required String productId,
    required String cardId,
    required String otpCode,
  }) async {
    _checkSession();
    if (_inAppPurchase == null) {
      throw InAppPurchaseError('No in-app purchase service configured.');
    }
    if (!_otpService.validateVerificationCode(_currentUser!.mobileNumber, otpCode)) {
      throw RegistrationError('Invalid OTP.');
    }
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw TransactionError('Card not found.'),
    );

    if (card.isExpired()) {
      return TransactionResult(
        status: TransactionStatus.cardExpired,
        message: 'Card has expired. Please use a valid card.',
        amount: 0.0,
      );
    }

    final result = await _inAppPurchase!.purchaseProduct(productId, cardId);
    if (result.status == TransactionStatus.success) {
      _logTransaction(
        amount: result.amount,
        status: result.status,
        cardId: cardId,
        message: result.message,
        feeAmount: 0.0,
        locationGeoHash: 'in_app',
        riskScore: 0,
        securityFlag: 'IN_APP_PURCHASE',
      );
    }
    return result;
  }

  Future<TransactionResult> handleInAppPurchaseVerification({
    required PurchaseDetails purchase,
    required String cardId,
    required double amount,
  }) async {
    _checkSession();
    if (_inAppPurchase == null) {
      throw InAppPurchaseError('No in-app purchase service configured.');
    }
    final card = _currentUser!.registeredCards.firstWhere(
      (c) => c.cardId == cardId,
      orElse: () => throw TransactionError('Card not found.'),
    );

    final isVerified = await _inAppPurchase!.verifyPurchase(purchase);
    if (isVerified) {
      final cardDataForToken = jsonEncode({
        'cardNumber': card.unencryptedCardNumber,
        'cvv2': DataProtector.decrypt(card.encryptedCvv2),
      });
      final paymentToken = PaymentToken(
        encryptedCardData: DataProtector.encrypt(cardDataForToken),
        cardId: card.cardId,
        expirationTime: DateTime.now().add(const Duration(minutes: 5)),
        signature: 'SIMULATED_SIGNATURE_${card.cardId}',
      );

      final topUpResult = await _nfcDevice.topUpBalance(
        token: paymentToken,
        amount: amount,
        pin: null,
      );

      if (topUpResult.status == TransactionStatus.success) {
        _logTransaction(
          amount: amount,
          status: topUpResult.status,
          cardId: cardId,
          message: 'In-app purchase verified. New balance: ${topUpResult.message.split('New Balance: ').last}',
          feeAmount: 0.0,
          locationGeoHash: 'in_app',
          riskScore: 0,
          securityFlag: 'IN_APP_PURCHASE_VERIFIED',
        );
        return topUpResult;
      } else {
        return topUpResult;
      }
    }
    return TransactionResult(
      status: TransactionStatus.failure,
      message: 'In-app purchase verification failed.',
      amount: amount,
    );
  }
}

void main() {
  runApp(KahrobaApp());
}

class KahrobaApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Kahroba Payment',
      theme: ThemeData(
        primarySwatch: Colors.teal,
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
        visualDensity: VisualDensity.adaptivePlatformDensity,
        textTheme: TextTheme(
          headlineMedium: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.teal[900]),
          bodyMedium: TextStyle(fontSize: 16, color: Colors.grey[800]),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            padding: EdgeInsets.symmetric(vertical: 16, horizontal: 24),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
          filled: true,
          fillColor: Colors.teal[50],
        ),
      ),
      home: LoginScreen(),
    );
  }
}

class LoginScreen extends StatefulWidget {
  @override
  _LoginScreenState createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _kahrobaService = KahrobaService(inAppPurchase: KahrobaInAppPurchase(KahrobaService()));
  final _mobileController = TextEditingController();
  final _passwordController = TextEditingController();
  String? _errorMessage;
  bool _isLoading = false;

  void _login() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      final success = _kahrobaService.login(
        _mobileController.text,
        _passwordController.text,
      );
      if (success) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (_) => HomeScreen(kahrobaService: _kahrobaService)),
        );
      } else {
        setState(() {
          _errorMessage = 'Invalid mobile number or password.';
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text('Kahroba Payment', style: Theme.of(context).textTheme.headlineMedium),
              SizedBox(height: 32),
              TextField(
                controller: _mobileController,
                decoration: InputDecoration(labelText: 'Mobile Number'),
                keyboardType: TextInputType.phone,
              ),
              SizedBox(height: 16),
              TextField(
                controller: _passwordController,
                decoration: InputDecoration(labelText: 'Password'),
                obscureText: true,
              ),
              if (_errorMessage != null) ...[
                SizedBox(height: 16),
                Text(_errorMessage!, style: TextStyle(color: Colors.red)),
              ],
              SizedBox(height: 24),
              _isLoading
                  ? CircularProgressIndicator()
                  : ElevatedButton(
                      onPressed: _login,
                      child: Text('Login'),
                    ),
            ],
          ),
        ),
      ),
    );
  }
}

class HomeScreen extends StatefulWidget {
  final KahrobaService kahrobaService;

  HomeScreen({required this.kahrobaService});

  @override
  _HomeScreenState createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _selectedIndex = 0;
  late List<Widget> _screens;

  @override
  void initState() {
    super.initState();
    _screens = [
      CardManagementScreen(kahrobaService: widget.kahrobaService),
      PaymentScreen(kahrobaService: widget.kahrobaService),
      TopUpScreen(kahrobaService: widget.kahrobaService),
      TransactionHistoryScreen(kahrobaService: widget.kahrobaService),
      InAppPurchaseScreen(kahrobaService: widget.kahrobaService),
    ];
  }

  void _onItemTapped(int index) {
    setState(() {
      _selectedIndex = index;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Kahroba Wallet'),
        actions: [
          IconButton(
            icon: Icon(Icons.logout),
            onPressed: () {
              widget.kahrobaService.logout();
              Navigator.pushReplacement(
                context,
                MaterialPageRoute(builder: (_) => LoginScreen()),
              );
            },
          ),
        ],
      ),
      body: _screens[_selectedIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: _onItemTapped,
        selectedItemColor: Colors.teal,
        unselectedItemColor: Colors.grey,
        items: [
          BottomNavigationBarItem(icon: Icon(Icons.credit_card), label: 'Cards'),
          BottomNavigationBarItem(icon: Icon(Icons.payment), label: 'Pay'),
          BottomNavigationBarItem(icon: Icon(Icons.add_circle), label: 'Top-Up'),
          BottomNavigationBarItem(icon: Icon(Icons.history), label: 'History'),
          BottomNavigationBarItem(icon: Icon(Icons.shop), label: 'Purchases'),
        ],
      ),
    );
  }
}

class CardManagementScreen extends StatefulWidget {
  final KahrobaService kahrobaService;

  CardManagementScreen({required this.kahrobaService});

  @override
  _CardManagementScreenState createState() => _CardManagementScreenState();
}

class _CardManagementScreenState extends State<CardManagementScreen> {
  final _cardAliasController = TextEditingController();
  final _cardNumberController = TextEditingController();
  final _cvv2Controller = TextEditingController();
  final _expiryDateController = TextEditingController();
  final _nationalIdController = TextEditingController();
  final _passwordController = TextEditingController();
  final _otpController = TextEditingController();
  String? _errorMessage;

  void _addCard() async {
    try {
      final card = BankCard(
        cardId: 'card${DateTime.now().millisecondsSinceEpoch}',
        cardAlias: _cardAliasController.text,
        cardNumber: _cardNumberController.text,
        cvv2: _cvv2Controller.text,
        expiryDate: _expiryDateController.text,
        nationalIdOwner: _nationalIdController.text,
      );
      widget.kahrobaService.addCard(
        card,
        _passwordController.text,
        _otpController.text,
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Card added successfully')),
      );
      setState(() {}); // Refresh card list
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text('Manage Cards', style: Theme.of(context).textTheme.headlineMedium),
          Expanded(
            child: FutureBuilder<List<Map<String, dynamic>>>(
              future: Future.value(widget.kahrobaService.getRegisteredCards()),
              builder: (context, snapshot) {
                if (!snapshot.hasData) return CircularProgressIndicator();
                final cards = snapshot.data!;
                return ListView.builder(
                  itemCount: cards.length,
                  itemBuilder: (context, index) {
                    final card = cards[index];
                    return Card(
                      elevation: 4,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      child: ListTile(
                        title: Text(card['cardAlias']),
                        subtitle: Text(card['maskedCardNumber']),
                        trailing: card['isDefault'] ? Icon(Icons.check_circle, color: Colors.teal) : null,
                        onTap: () {
                          widget.kahrobaService.setDefaultCard(
                            card['cardId'],
                            _passwordController.text,
                            _otpController.text,
                          );
                          setState(() {});
                        },
                      ),
                    );
                  },
                );
              },
            ),
          ),
          TextField(
            controller: _cardAliasController,
            decoration: InputDecoration(labelText: 'Card Alias'),
          ),
          TextField(
            controller: _cardNumberController,
            decoration: InputDecoration(labelText: 'Card Number'),
            keyboardType: TextInputType.number,
          ),
          TextField(
            controller: _cvv2Controller,
            decoration: InputDecoration(labelText: 'CVV2'),
            keyboardType: TextInputType.number,
          ),
          TextField(
            controller: _expiryDateController,
            decoration: InputDecoration(labelText: 'Expiry Date (MM/YY)'),
          ),
          TextField(
            controller: _nationalIdController,
            decoration: InputDecoration(labelText: 'National ID'),
            keyboardType: TextInputType.number,
          ),
          TextField(
            controller: _passwordController,
            decoration: InputDecoration(labelText: 'Password'),
            obscureText: true,
          ),
          TextField(
            controller: _otpController,
            decoration: InputDecoration(labelText: 'OTP'),
            keyboardType: TextInputType.number,
          ),
          if (_errorMessage != null) ...[
            SizedBox(height: 16),
            Text(_errorMessage!, style: TextStyle(color: Colors.red)),
          ],
          SizedBox(height: 16),
          ElevatedButton(
            onPressed: _addCard,
            child: Text('Add Card'),
          ),
        ],
      ),
    );
  }
}

class PaymentScreen extends StatefulWidget {
  final KahrobaService kahrobaService;

  PaymentScreen({required this.kahrobaService});

  @override
  _PaymentScreenState createState() => _PaymentScreenState();
}

class _PaymentScreenState extends State<PaymentScreen> {
  final _amountController = TextEditingController();
  final _merchantIdController = TextEditingController();
  final _pinController = TextEditingController();
  String? _errorMessage;
  bool _isLoading = false;

  void _processPayment() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      final result = await widget.kahrobaService.processPayment(
        amount: double.parse(_amountController.text),
        context: TransactionContext(
          merchantId: _merchantIdController.text,
          locationGeoHash: 'simulated',
        ),
        pin: _pinController.text.isEmpty ? null : _pinController.text,
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(result.message)),
      );
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text('Make a Payment', style: Theme.of(context).textTheme.headlineMedium),
          TextField(
            controller: _amountController,
            decoration: InputDecoration(labelText: 'Amount'),
            keyboardType: TextInputType.number,
          ),
          TextField(
            controller: _merchantIdController,
            decoration: InputDecoration(labelText: 'Merchant ID'),
          ),
          TextField(
            controller: _pinController,
            decoration: InputDecoration(labelText: 'PIN (if required)'),
            keyboardType: TextInputType.number,
            obscureText: true,
          ),
          if (_errorMessage != null) ...[
            SizedBox(height: 16),
            Text(_errorMessage!, style: TextStyle(color: Colors.red)),
          ],
          SizedBox(height: 16),
          _isLoading
              ? CircularProgressIndicator()
              : ElevatedButton(
                  onPressed: _processPayment,
                  child: Text('Pay Now'),
                ),
        ],
      ),
    );
  }
}

class TopUpScreen extends StatefulWidget {
  final KahrobaService kahrobaService;

  TopUpScreen({required this.kahrobaService});

  @override
  _TopUpScreenState createState() => _TopUpScreenState();
}

class _TopUpScreenState extends State<TopUpScreen> {
  final _amountController = TextEditingController();
  final _cardIdController = TextEditingController();
  String? _errorMessage;
  bool _isLoading = false;

  void _processTopUp() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      final result = await widget.kahrobaService.processTopUp(
        amount: double.parse(_amountController.text),
        cardId: _cardIdController.text,
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(result.message)),
      );
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text('Top-Up Card', style: Theme.of(context).textTheme.headlineMedium),
          TextField(
            controller: _amountController,
            decoration: InputDecoration(labelText: 'Amount'),
            keyboardType: TextInputType.number,
          ),
          TextField(
            controller: _cardIdController,
            decoration: InputDecoration(labelText: 'Card ID'),
          ),
          if (_errorMessage != null) ...[
            SizedBox(height: 16),
            Text(_errorMessage!, style: TextStyle(color: Colors.red)),
          ],
          SizedBox(height: 16),
          _isLoading
              ? CircularProgressIndicator()
              : ElevatedButton(
                  onPressed: _processTopUp,
                  child: Text('Top-Up'),
                ),
        ],
      ),
    );
  }
}

class TransactionHistoryScreen extends StatelessWidget {
  final KahrobaService kahrobaService;

  TransactionHistoryScreen({required this.kahrobaService});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text('Transaction History', style: Theme.of(context).textTheme.headlineMedium),
          Expanded(
            child: FutureBuilder<List<KahrobaTransaction>>(
              future: Future.value(kahrobaService.getTransactionLog()),
              builder: (context, snapshot) {
                if (!snapshot.hasData) return CircularProgressIndicator();
                final transactions = snapshot.data!;
                return ListView.builder(
                  itemCount: transactions.length,
                  itemBuilder: (context, index) {
                    final tx = transactions[index];
                    return Card(
                      elevation: 4,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      child: ListTile(
                        title: Text('Amount: ${tx.amount.toStringAsFixed(2)}'),
                        subtitle: Text(
                          'Status: ${tx.status.name}\n'
                          'Time: ${DateFormat('yyyy-MM-dd HH:mm').format(tx.timestamp)}\n'
                          'Message: ${tx.message}',
                        ),
                        isThreeLine: true,
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

class InAppPurchaseScreen extends StatefulWidget {
  final KahrobaService kahrobaService;

  InAppPurchaseScreen({required this.kahrobaService});

  @override
  _InAppPurchaseScreenState createState() => _InAppPurchaseScreenState();
}

class _InAppPurchaseScreenState extends State<InAppPurchaseScreen> {
  final _productIdController = TextEditingController();
  final _cardIdController = TextEditingController();
  final _otpController = TextEditingController();
  String? _errorMessage;
  bool _isLoading = false;
  List<ProductDetails> _products = [];
  StreamSubscription<List<PurchaseDetails>>? _subscription;

  @override
  void initState() {
    super.initState();
    _fetchProducts();
    final purchaseStream = InAppPurchase.instance.purchaseStream;
    _subscription = purchaseStream.listen((List<PurchaseDetails> purchaseDetailsList) {
      _listenToPurchaseUpdated(purchaseDetailsList);
    });
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }

  void _fetchProducts() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      // Define product IDs for in-app purchases
      const List<String> productIds = [
        'kahroba_premium_10',
        'kahroba_premium_50',
        'kahroba_premium_100',
      ];
      final products = await widget.kahrobaService.fetchInAppProducts(productIds);
      setState(() {
        _products = products;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _listenToPurchaseUpdated(List<PurchaseDetails> purchaseDetailsList) async {
    for (var purchase in purchaseDetailsList) {
      if (purchase.status == PurchaseStatus.purchased || purchase.status == PurchaseStatus.restored) {
        final amount = double.tryParse(purchase.productID.replaceAll(RegExp(r'[^\d.]'), '')) ?? 0.0;
        final result = await widget.kahrobaService.handleInAppPurchaseVerification(
          purchase: purchase,
          cardId: _cardIdController.text,
          amount: amount,
        );
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(result.message)),
        );
      } else if (purchase.status == PurchaseStatus.error) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Purchase error: ${purchase.error?.message ?? "Unknown error"}')),
        );
      }
    }
  }

  void _purchaseProduct() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    try {
      final result = await widget.kahrobaService.processInAppPurchase(
        productId: _productIdController.text,
        cardId: _cardIdController.text,
        otpCode: _otpController.text,
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(result.message)),
      );
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text('In-App Purchases', style: Theme.of(context).textTheme.headlineMedium),
          Expanded(
            child: _isLoading
                ? Center(child: CircularProgressIndicator())
                : _products.isEmpty
                    ? Center(child: Text('No products available'))
                    : ListView.builder(
                        itemCount: _products.length,
                        itemBuilder: (context, index) {
                          final product = _products[index];
                          return Card(
                            elevation: 4,
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                            child: ListTile(
                              title: Text(product.title),
                              subtitle: Text('${product.description}\nPrice: ${product.price}'),
                              onTap: () {
                                _productIdController.text = product.id;
                                _purchaseProduct();
                              },
                            ),
                          );
                        },
                      ),
          ),
          TextField(
            controller: _productIdController,
            decoration: InputDecoration(labelText: 'Product ID'),
          ),
          TextField(
            controller: _cardIdController,
            decoration: InputDecoration(labelText: 'Card ID'),
          ),
          TextField(
            controller: _otpController,
            decoration: InputDecoration(labelText: 'OTP'),
            keyboardType: TextInputType.number,
          ),
          if (_errorMessage != null) ...[
            SizedBox(height: 16),
            Text(_errorMessage!, style: TextStyle(color: Colors.red)),
          ],
          SizedBox(height: 16),
          _isLoading
              ? CircularProgressIndicator()
              : ElevatedButton(
                  onPressed: _purchaseProduct,
                  child: Text('Purchase'),
                ),
        ],
      ),
    );
  }
}

class _CardManagementScreenState extends State<CardManagementScreen> {
  final _cardAliasController = TextEditingController();
  final _cardNumberController = TextEditingController();
  final _cvv2Controller = TextEditingController();
  final _expiryDateController = TextEditingController();
  final _nationalIdController = TextEditingController();
  final _passwordController = TextEditingController();
  final _otpController = TextEditingController();
  String? _errorMessage;
  String _cardType = '';

  void _addCard() async {
    try {
      final card = BankCard(
        cardId: 'card${DateTime.now().millisecondsSinceEpoch}',
        cardAlias: _cardAliasController.text,
        cardNumber: _cardNumberController.text.replaceAll(' ', ''), // Remove spaces from card number
        cvv2: _cvv2Controller.text,
        expiryDate: _expiryDateController.text,
        nationalIdOwner: _nationalIdController.text,
      );
      widget.kahrobaService.addCard(
        card,
        _passwordController.text,
        _otpController.text,
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Card added successfully')),
      );
      setState(() {
        _cardAliasController.clear();
        _cardNumberController.clear();
        _cvv2Controller.clear();
        _expiryDateController.clear();
        _nationalIdController.clear();
        _passwordController.clear();
        _otpController.clear();
        _cardType = '';
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.all(16.0),
      child: SingleChildScrollView(
        child: Column(
          children: [
            Text('Manage Cards', style: Theme.of(context).textTheme.headlineMedium),
            SizedBox(height: 16),
            Expanded(
              child: FutureBuilder<List<Map<String, dynamic>>>(
                future: Future.value(widget.kahrobaService.getRegisteredCards()),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) return CircularProgressIndicator();
                  final cards = snapshot.data!;
                  return ListView.builder(
                    shrinkWrap: true,
                    physics: NeverScrollableScrollPhysics(),
                    itemCount: cards.length,
                    itemBuilder: (context, index) {
                      final card = cards[index];
                      return Card(
                        elevation: 4,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        child: ListTile(
                          title: Text(card['cardAlias']),
                          subtitle: Text('${card['maskedCardNumber']}\nBalance: ${card['balance']?.toStringAsFixed(2) ?? 'Loading...'}'),
                          trailing: card['isDefault'] ? Icon(Icons.check_circle, color: Colors.teal) : null,
                          onTap: () {
                            widget.kahrobaService.setDefaultCard(
                              card['cardId'],
                              _passwordController.text,
                              _otpController.text,
                            );
                            setState(() {});
                          },
                        ),
                      );
                    },
                  );
                },
              ),
            ),
            CreditCardForm(
              cardNumber: _cardNumberController.text,
              expiryDate: _expiryDateController.text,
              cardHolderName: _cardAliasController.text,
              cvvCode: _cvv2Controller.text,
              onCreditCardModelChange: (CreditCardModel model) {
                setState(() {
                  _cardNumberController.text = model.cardNumber;
                  _expiryDateController.text = model.expiryDate;
                  _cvv2Controller.text = model.cvvCode;
                  _cardAliasController.text = model.cardHolderName;
                  _cardType = model.cardNumber.isNotEmpty ? getCardType(model.cardNumber).toString() : '';
                });
              },
              themeColor: Colors.teal,
              formKey: GlobalKey<FormState>(),
              cardNumberDecoration: InputDecoration(
                labelText: 'Card Number',
                hintText: 'XXXX XXXX XXXX XXXX',
              ),
              expiryDateDecoration: InputDecoration(
                labelText: 'Expiry Date',
                hintText: 'MM/YY',
              ),
              cvvCodeDecoration: InputDecoration(
                labelText: 'CVV',
                hintText: 'XXX',
              ),
              cardHolderDecoration: InputDecoration(
                labelText: 'Card Alias',
              ),
            ),
            TextField(
              controller: _nationalIdController,
              decoration: InputDecoration(labelText: 'National ID'),
              keyboardType: TextInputType.number,
            ),
            TextField(
              controller: _passwordController,
              decoration: InputDecoration(labelText: 'Password'),
              obscureText: true,
            ),
            TextField(
              controller: _otpController,
              decoration: InputDecoration(labelText: 'OTP'),
              keyboardType: TextInputType.number,
            ),
            if (_cardType.isNotEmpty) ...[
              SizedBox(height: 16),
              Text('Card Type: $_cardType', style: TextStyle(fontWeight: FontWeight.bold)),
            ],
            if (_errorMessage != null) ...[
              SizedBox(height: 16),
              Text(_errorMessage!, style: TextStyle(color: Colors.red)),
            ],
            SizedBox(height: 16),
            ElevatedButton(
              onPressed: _addCard,
              child: Text('Add Card'),
            ),
          ],
        ),
      ),
    );
  }

  // Helper function to detect card type
  CardType getCardType(String cardNumber) {
    return CardUtils.getCardTypeFrmNumber(cardNumber.replaceAll(' ', ''));
  }
}
