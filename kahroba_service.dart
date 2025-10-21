// kahroba_service.dart
// Advanced Dart package for simulating Kahroba smart payment system
// Goal: Provide modular business logic with multi-card support, transaction history, OTP, dynamic limits, and advanced security layers.

import 'dart:convert';
import 'dart:math';

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

// -----------------------------------------------------------------------------
// 2. Security Utilities
// -----------------------------------------------------------------------------

class DataProtector {
  // Static key for simulation (in production, use KeyStore/HSM with AES-256-GCM via pointycastle)
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
      final decodedBytes = base64Decode(encryptedData);
      final keyBytes = utf8.encode(_encryptionKey);
      final decryptedBytes = List<int>.generate(decodedBytes.length, (i) {
        return decodedBytes[i] ^ keyBytes[i % keyBytes.length];
      });
      return utf8.decode(decryptedBytes);
    } catch (e) {
      throw RegistrationError('Invalid card data. Please try again.');
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
          'Payment successful. (Card: ****${decryptedCardNumber.substring(decryptedCardNumber.length - 4)}) Balance: ${newBalance.toStringAsFixed(2)}',
      amount: transactionAmount,
    );
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

  final Map<String, OtpEntry> _otpStore = {};
  final Map<String, int> _otpAttempts = {};
  static const int _maxOtpAttempts = 3;
  final Random _random = Random();

  final Map<String, double> _dailySpending = {};
  DateTime _lastTransactionDate = DateTime.now();

  DateTime _lastTransactionTime = DateTime.fromMicrosecondsSinceEpoch(0);
  String? _lastTransactionGeoHash;
  static const Duration _cooldownPeriod = Duration(seconds: 5);
  static const int _fraudVelocityMinutes = 10;
  static const int _highRiskScoreThreshold = 70;

  final Map<String, int> _securityIncidentCount = {};

  KahrobaService({NfcDeviceInterface? nfcDevice}) : _nfcDevice = nfcDevice ?? NfcSimulator();

  class OtpEntry {
    final String code;
    final DateTime expiryTime;

    OtpEntry(this.code, {required this.expiryTime});
  }

  String requestOtpForUser() {
    _checkSession();
    return _generateVerificationCode(_currentUser!.mobileNumber);
  }

  String _generateVerificationCode(String mobileNumber) {
    final code = (_random.nextInt(899999) + 100000).toString();
    _otpStore[mobileNumber] = OtpEntry(
      code,
      expiryTime: DateTime.now().add(Duration(minutes: 5)),
    );
    _otpAttempts[mobileNumber] = 0; // Reset attempts on new OTP
    return code;
  }

  bool _validateVerificationCode(String mobileNumber, String code) {
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
    _otpStore.remove(mobileNumber); // Clear OTP after successful validation
    _otpAttempts.remove(mobileNumber);
    return true;
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
    int score = 0;
    if (amount > 500.0) score += 30;
    if (amount > 1500.0) score += 40;
    if (_lastTransactionGeoHash != null &&
        _lastTransactionGeoHash != currentGeoHash &&
        DateTime.now().difference(_lastTransactionTime).inMinutes < _fraudVelocityMinutes) {
      score += 50;
    }
    final userId = _currentUser?.mobileNumber ?? 'unknown';
    score += (_securityIncidentCount[userId] ?? 0) * 10;
    return score;
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
    // Simulate secure hashing (in production, use bcrypt or Argon2)
    final passwordHash = 'SECURE_HASH_${primaryPassword.hashCode}';
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
  }

  void setDefaultCard(String cardId, String password, String otpCode) {
    _checkSession();
    if (!_validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != 'SECURE_HASH_${password.hashCode}') {
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
    if (!_validateVerificationCode(_currentUser!.mobileNumber, otpCode) ||
        _currentUser!.primaryPasswordHash != 'SECURE_HASH_${password.hashCode}') {
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

    if (riskScore >= _highRiskScoreThreshold) {
      securityFlag = 'DRS_HIGH_RISK_FORCED_MFA';
      defaultCard.authPolicy = AuthPolicy.dynamicMFA;
    } else if (_lastTransactionGeoHash != null &&
        _lastTransactionGeoHash != context.locationGeoHash &&
        DateTime.now().difference(_lastTransactionTime).inMinutes < _fraudVelocityMinutes) {
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
      signature: 'SIMULATED_SIGNATURE_${defaultCard.cardId}', // In production, use RSA/ECDSA
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
    if (user != null && user.primaryPasswordHash == 'SECURE_HASH_${password.hashCode}') {
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
    return _transactionLog
        .where((log) => userCardIds.contains(log.cardId))
        .toList()
      ..sort((a, b) => b.timestamp.compareTo(a.timestamp));
  }
}