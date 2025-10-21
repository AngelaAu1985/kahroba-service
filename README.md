The Kahroba Smart Payment System is a robust Flutter package designed for secure and seamless digital transactions. Leveraging `flutter_credit_card` for intuitive card input and validation, and `in_app_purchase` for flexible top-ups and subscriptions, it offers a comprehensive solution for mobile payments. With features like NFC simulation, multi-currency support, fraud detection, and transaction receipt generation, Kahroba ensures a user-friendly experience while prioritizing security through OTP verification and card suspension capabilities. Ideal for developers building modern payment applications, Kahroba combines modularity and scalability for efficient integration.


import 'package:flutter/material.dart';
import 'package:flutter_credit_card/flutter_credit_card.dart';
import 'package:in_app_purchase/in_app_purchase.dart';
import 'package:share_plus/share_plus.dart';
import 'kahroba_app.dart'; // Import the main app file

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(TestKahrobaApp());
}

class TestKahrobaApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: TestScaffold(),
      theme: ThemeData(
        primarySwatch: Colors.teal,
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
    );
  }
}

class TestScaffold extends StatefulWidget {
  @override
  _TestScaffoldState createState() => _TestScaffoldState();
}

class _TestScaffoldState extends State<TestScaffold> {
  final kahrobaService = KahrobaService(
    inAppPurchase: KahrobaInAppPurchase(KahrobaService()),
    paymentGateway: ZarinpalGateway(
      merchantId: 'your-zarinpal-merchant-id',
      callbackUrl: 'https://your-callback-url.com',
      isSandbox: true,
    ),
  );
  String statusMessage = 'Ready to start Kahroba demo';
  bool isLoading = false;

  @override
  void initState() {
    super.initState();
    runKahrobaDemo();
  }

  Future<void> runKahrobaDemo() async {
    setState(() {
      isLoading = true;
      statusMessage = 'Starting Kahroba demo...';
    });

    try {
      // Step 1: Register a new user
      setState(() => statusMessage = 'Step 1: Registering user...');
      final initialCard = BankCard(
        cardId: 'card001',
        cardAlias: 'My Visa Card',
        cardNumber: '1234567890123456',
        cvv2: '123',
        expiryDate: '12/27',
        nationalIdOwner: '1234567890',
      );
      await kahrobaService.registerUser(
        mobileNumber: '09123456789',
        nationalId: '1234567890',
        primaryPassword: 'securePassword123',
        initialCard: initialCard,
      );
      setState(() => statusMessage = 'User registered successfully.');

      // Step 2: Simulate login via LoginScreen
      setState(() => statusMessage = 'Step 2: Simulating login...');
      final loginSuccess = kahrobaService.login('09123456789', 'securePassword123');
      if (loginSuccess) {
        setState(() => statusMessage = 'Login successful. Navigating to HomeScreen...');
        await Future.delayed(Duration(seconds: 1)); // Simulate navigation
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => HomeScreen(kahrobaService: kahrobaService)),
        );
      } else {
        throw Exception('Login failed.');
      }

      // Step 3: Request OTP and validate
      setState(() => statusMessage = 'Step 3: Requesting OTP...');
      final otpCode = kahrobaService.requestOtpForUser();
      setState(() => statusMessage = 'OTP generated: $otpCode');
      bool isOtpValid = kahrobaService._otpService.validateVerificationCode('09123456789', otpCode);
      setState(() => statusMessage = 'OTP validation: ${isOtpValid ? 'Success' : 'Failed'}');

      // Step 4: Simulate adding a card via CardManagementScreen
      setState(() => statusMessage = 'Step 4: Adding a second card...');
      final newCard = BankCard(
        cardId: 'card002',
        cardAlias: 'My Mastercard',
        cardNumber: '5555555555554444',
        cvv2: '456',
        expiryDate: '11/26',
        nationalIdOwner: '1234567890',
      );
      kahrobaService.addCard(newCard, 'securePassword123', otpCode);
      setState(() => statusMessage = 'Second card added successfully.');

      // Step 5: Simulate setting default card
      setState(() => statusMessage = 'Step 5: Setting card002 as default...');
      kahrobaService.setDefaultCard('card002', 'securePassword123', otpCode);
      setState(() => statusMessage = 'Default card set to card002.');

      // Step 6: Simulate payment in EUR
      setState(() => statusMessage = 'Step 6: Processing payment of 50 EUR...');
      final paymentResult = await kahrobaService.processPayment(
        amount: 50.0,
        context: TransactionContext(merchantId: 'merchant123', locationGeoHash: 'simulated_eur'),
        pin: '2222',
        currency: Currency.EUR,
      );
      setState(() => statusMessage = 'Payment result: ${paymentResult.message}');

      // Step 7: Simulate top-up in IRR
      setState(() => statusMessage = 'Step 7: Topping up card001 with 100,000 IRR...');
      final topUpResult = await kahrobaService.processTopUp(
        amount: 100000.0,
        cardId: 'card001',
        pin: '1111',
      );
      setState(() => statusMessage = 'Top-up result: ${topUpResult.message}');

      // Step 8: Simulate in-app purchase
      setState(() => statusMessage = 'Step 8: Initiating in-app purchase...');
      final purchaseResult = await kahrobaService.processInAppPurchase(
        productId: 'kahroba_premium_10',
        cardId: 'card002',
        otpCode: otpCode,
      );
      setState(() => statusMessage = 'Purchase result: ${purchaseResult.message}');

      // Step 9: Simulate subscription purchase
      setState(() => statusMessage = 'Step 9: Initiating subscription purchase...');
      final subscriptionResult = await kahrobaService.processSubscriptionPurchase(
        productId: 'kahroba_premium_monthly',
        otpCode: otpCode,
      );
      setState(() => statusMessage = 'Subscription result: ${subscriptionResult.message}');

      // Step 10: Simulate subscription restoration
      setState(() => statusMessage = 'Step 10: Restoring subscriptions...');
      await InAppPurchase.instance.restorePurchases();
      setState(() => statusMessage = 'Subscriptions restored.');

      // Step 11: Simulate card suspension
      setState(() => statusMessage = 'Step 11: Suspending card001...');
      kahrobaService.suspendCard('card001', 'securePassword123', otpCode);
      setState(() => statusMessage = 'Card001 suspended successfully.');

      // Step 12: Simulate error case (payment with suspended card)
      setState(() => statusMessage = 'Step 12: Attempting payment with suspended card...');
      try {
        await kahrobaService.processPayment(
          amount: 20.0,
          context: TransactionContext(merchantId: 'merchant123', locationGeoHash: 'simulated'),
          pin: '1111',
          currency: Currency.IRR,
        );
      } catch (e) {
        setState(() => statusMessage = 'Expected error: $e');
      }

      // Step 13: Simulate error case (invalid OTP)
      setState(() => statusMessage = 'Step 13: Attempting card reactivation with invalid OTP...');
      try {
        kahrobaService.reactivateCard('card001', 'securePassword123', 'wrong_otp');
      } catch (e) {
        setState(() => statusMessage = 'Expected error: $e');
      }

      // Step 14: View transaction history and share receipt
      setState(() => statusMessage = 'Step 14: Fetching transaction history...');
      final transactions = kahrobaService.getTransactionLog();
      if (transactions.isNotEmpty) {
        final receipt = kahrobaService.generateTransactionReceipt(transactions.first);
        setState(() => statusMessage = 'Generated receipt for first transaction.');
        await Share.share(receipt, subject: 'Kahroba Transaction Receipt');
      }

      // Step 15: Display card balances
      setState(() => statusMessage = 'Step 15: Fetching card balances...');
      final cards = await kahrobaService.getRegisteredCardsWithBalances();
      String balanceInfo = cards.map((card) => 
        'Card ${card['cardAlias']}: ${card['balance'].toStringAsFixed(2)} IRR, ${card['isSuspended'] ? 'Suspended' : 'Active'}'
      ).join('\n');
      setState(() => statusMessage = 'Card balances:\n$balanceInfo');

    } catch (e) {
      setState(() => statusMessage = 'Error: $e');
    } finally {
      setState(() => isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Kahroba Demo')),
      body: Padding(
        padding: EdgeInsets.all(16.0),
        child: Column(
          children: [
            Text('Demo Status', style: Theme.of(context).textTheme.headlineMedium),
            SizedBox(height: 16),
            Expanded(child: Text(statusMessage)),
            if (isLoading) CircularProgressIndicator(),
            SizedBox(height: 16),
            ElevatedButton(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => HomeScreen(kahrobaService: kahrobaService)),
              ),
              child: Text('Open Kahroba Wallet'),
            ),
          ],
        ),
      ),
    );
  }
}

// Simulate CardManagementScreen interaction
void simulateCardManagement(BuildContext context, KahrobaService kahrobaService) {
  Navigator.push(
    context,
    MaterialPageRoute(builder: (_) => CardManagementScreen(kahrobaService: kahrobaService)),
  );
  // Simulate user filling CreditCardForm
  final formState = GlobalKey<FormState>();
  final cardModel = CreditCardModel(
    cardNumber: '5555555555554444',
    expiryDate: '11/26',
    cardHolderName: 'My Mastercard',
    cvvCode: '456',
    isCvvFocused: false,
  );
  // In real UI, CreditCardForm would update controllers and validate input
  print('Simulated CreditCardForm input: ${cardModel.cardNumber}, Type: ${CardUtils.getCardTypeFrmNumber(cardModel.cardNumber)}');
}

// Simulate PaymentScreen interaction
void simulatePayment(BuildContext context, KahrobaService kahrobaService) async {
  Navigator.push(
    context,
    MaterialPageRoute(builder: (_) => PaymentScreen(kahrobaService: kahrobaService)),
  );
  // Simulate user input
  final amount = 50.0;
  final merchantId = 'merchant123';
  final pin = '2222';
  final currency = Currency.EUR;
  final result = await kahrobaService.processPayment(
    amount: amount,
    context: TransactionContext(merchantId: merchantId, locationGeoHash: 'simulated_eur'),
    pin: pin,
    currency: currency,
  );
  print('Simulated Payment: ${result.message}');
}

// Simulate InAppPurchaseScreen interaction
void simulateInAppPurchase(BuildContext context, KahrobaService kahrobaService) async {
  Navigator.push(
    context,
    MaterialPageRoute(builder: (_) => InAppPurchaseScreen(kahrobaService: kahrobaService)),
  );
  // Simulate fetching products
  final products = await kahrobaService.fetchInAppProducts([
    'kahroba_premium_10',
    'kahroba_premium_monthly',
  ]);
  print('Available products: ${products.map((p) => p.title).join(", ")}');
  
  // Simulate purchase
  final otpCode = kahrobaService.requestOtpForUser();
  final result = await kahrobaService.processInAppPurchase(
    productId: 'kahroba_premium_10',
    cardId: 'card002',
    otpCode: otpCode,
  );
  print('Simulated In-App Purchase: ${result.message}');
} 
