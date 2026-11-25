import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import dns from 'node:dns';
import {
  MongoClient,
  ServerApiVersion,
  ObjectId,
  Collection,
  Db,
  UpdateFilter,
  Filter,
} from 'mongodb';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';

// Load environment variables from .env into process.env
dotenv.config();

// ============================================================================
// 1. CONFIGURATION & EXPRESS SETUP
// ============================================================================

const uri = process.env.MONGODB_URI;
const port = Number(process.env.PORT || process.env.MONGODB_PORT || 5000);
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
const dbName = process.env.AUTH_DB_NAME || process.env.DB_NAME || 'finova_db';

if (!uri) {
  console.error('Critical Error: MONGODB_URI environment variable is missing.');
  process.exit(1);
}

const app = express();

// Parse JSON bodies (2MB limit to support inline base64 KYC documents/photos) and HTTP cookies
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Allow requests from our Next.js frontend with credentials (cookies & Bearer JWTs)
app.use(
  cors({
    origin: clientUrl,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'Idempotency-Key'],
    exposedHeaders: ['Set-Cookie'],
  })
);

// ============================================================================
// 2. TYPES, INTERFACES & EXPRESS REQUEST AUGMENTATION
// ============================================================================

export type UserRole = 'admin' | 'staff' | 'customer';
export type UserAccountStatus = 'active' | 'deactivated' | 'blocked';
export type VerificationStatus = 'incomplete' | 'pending' | 'verified' | 'correction_required';
export type BankAccountType = 'Savings' | 'Current' | 'Business';
export type BankAccountStatus = 'Active' | 'Frozen' | 'Closed';
export type TransactionType =
  | 'Deposit'
  | 'Withdrawal'
  | 'Fund Transfer'
  | 'Loan Disbursement'
  | 'Loan Repayment';
export type TransactionStatus = 'Pending' | 'Completed' | 'Failed' | 'Reversed';
export type LoanStatus = 'Pending' | 'Under Review' | 'Approved' | 'Rejected' | 'Active' | 'Completed';

interface CustomJWTPayload extends JWTPayload {
  sub: string;
  id: string;
  role: UserRole;
  status: UserAccountStatus;
}

// Augment Express Request globally so `req.user` works cleanly in both Express v4 and v5
declare global {
  namespace Express {
    interface Request {
      user?: CustomJWTPayload;
    }
  }
}

// Matches Better-Auth's "user" collection schema in finova_db
interface UserDocument {
  _id?: ObjectId | string;
  id?: string;
  name?: string;
  email?: string;
  image?: string;
  role?: UserRole | 'user';
  status?: UserAccountStatus; // 'active' | 'deactivated' | 'blocked'
  kycVerified?: boolean;
  verificationStatus?: VerificationStatus;
  verificationNote?: string;
  verifiedByStaffId?: string;
  verifiedAt?: Date;
  phone?: string;
  address?: string;
  city?: string;
  dateOfBirth?: string;
  gender?: string;
  nationalId?: string;
  occupation?: string;
  nidDocumentUrl?: string;
  supportingDocumentUrl?: string;
  monthlyIncome?: number;
  employmentStatus?: string;
  transactionPinHash?: string; // Stored as "salt:scryptHash", never exposed in responses
  twoFactorEnabled?: boolean;
  twoFactorChallenge?: {
    codeHash: string;
    purpose: string;
    expiresAt: Date;
  } | null;
  createdAt?: Date;
  updatedAt?: Date;
}

// Dedicated "customerProfiles" collection storing Step 3 KYC info & document references
interface CustomerProfileDocument {
  _id?: ObjectId;
  userId: string;
  fullName: string;
  email: string;
  phone: string;
  dateOfBirth: string;
  gender: string;
  address: string;
  city: string;
  nationalId: string;
  occupation: string;
  employmentStatus?: string;
  monthlyIncome?: number;
  profilePhotoUrl?: string;
  nidDocumentUrl: string;
  nidDocumentName?: string;
  supportingDocumentUrl?: string;
  supportingDocumentName?: string;
  verificationStatus: VerificationStatus;
  verificationNote?: string;
  submittedAt?: Date;
  verifiedByStaffId?: string;
  verifiedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

interface BankAccountDocument {
  _id?: ObjectId;
  userId: string;
  accountNumber: string;
  accountType: BankAccountType;
  balance: number;
  status: BankAccountStatus;
  dailyTransferLimit: number;
  maxSingleTransaction: number;
  minBalance: number;
  createdAt: Date;
  updatedAt: Date;
}

interface AccountRequestDocument {
  _id?: ObjectId;
  requestCode: string;
  userId: string;
  accountType: BankAccountType;
  purpose: string;
  status: 'Pending' | 'Approved' | 'Rejected';
  reviewedBy?: string;
  reviewNote?: string;
  createdAccountId?: string;
  createdAccountNumber?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface TransactionDocument {
  _id?: ObjectId;
  transactionId: string;
  idempotencyKey?: string;
  userId: string;
  receiverUserId?: string;
  senderAccountId?: string;
  senderAccountNumber?: string;
  receiverAccountId?: string;
  receiverAccountNumber?: string;
  type: TransactionType;
  amount: number;
  fee: number;
  status: TransactionStatus;
  description: string;
  isSuspicious: boolean;
  suspiciousReason?: string;
  reviewedBy?: string;
  createdAt: Date;
}

interface DepositWithdrawRequestDocument {
  _id?: ObjectId;
  requestCode?: string;
  idempotencyKey?: string;
  userId: string;
  accountId: string;
  accountNumber: string;
  type: 'Deposit' | 'Withdrawal';
  amount: number;
  description: string;
  status: 'Pending' | 'Under Review' | 'Approved' | 'Rejected';
  forwardedByStaffId?: string;
  staffNote?: string;
  reviewedBy?: string;
  reviewNote?: string;
  transactionId?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface LoanInstallment {
  installmentNumber: number;
  dueDate: Date;
  amount: number;
  principal: number;
  interest: number;
  paidAmount?: number;
  status: 'Pending' | 'Paid';
  paidAt?: Date;
}

interface LoanDocument {
  _id?: ObjectId;
  userId: string;
  accountId: string;
  loanType: 'Personal' | 'Home' | 'Auto' | 'Business' | 'Education';
  requestedAmount: number;
  approvedAmount?: number;
  interestRate: number;
  durationMonths: number;
  monthlyIncome: number;
  employmentStatus: string;
  description: string;
  status: LoanStatus;
  remainingBalance: number;
  monthlyInstallment: number;
  staffNotes: Array<{ staffId: string; note: string; createdAt: Date }>;
  forwardedByStaffId?: string;
  reviewedByAdminId?: string;
  repaymentSchedule: LoanInstallment[];
  createdAt: Date;
  updatedAt: Date;
}

interface NotificationDocument {
  _id?: ObjectId;
  userId: string;
  title: string;
  message: string;
  type: 'transfer' | 'deposit' | 'withdrawal' | 'loan' | 'security' | 'account' | 'kyc';
  isRead: boolean;
  createdAt: Date;
}

interface BankSettingsDocument {
  _id: string; // Fixed key: 'global_limits'
  defaultDailyTransferLimit: number;
  defaultMaxSingleTransaction: number;
  defaultMinBalance: number;
  largeTransactionAlertThreshold: number;
  transferFeePercent: number;
  updatedAt: Date;
}

// ============================================================================
// 3. HELPER UTILITIES (Validation, Security, & Banking Calculations)
// ============================================================================

/** Safely extracts a single string param (fixes Express v5 `string | string[]` typing). */
function getParam(value: string | string[] | undefined): string {
  return Array.isArray(value)
    ? value[0]?.trim() || ''
    : typeof value === 'string'
    ? value.trim()
    : '';
}

/** Ensures a request field is a plain string to block NoSQL operator injection (e.g. {$gt: ""}). */
function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

/** Validates safe URLs (http://, https://, /, or bounded image/PDF base64 data URIs) to prevent XSS schemes like javascript:. */
function isSafeUrl(url: string): boolean {
  if (!url) return true;
  if (/^https?:\/\//i.test(url) || url.startsWith('/')) return true;
  if (/^data:(image\/(png|jpeg|jpg|webp)|application\/pdf);base64,[A-Za-z0-9+/=]+$/i.test(url)) {
    return url.length <= 750_000;
  }
  return false;
}

/** Strictly checks for a 24-character hex MongoDB ObjectId string. */
function isValidObjectId(id: string): boolean {
  return /^[a-fA-F0-9]{24}$/.test(id) && ObjectId.isValid(id);
}

/** Builds a MongoDB filter matching Better-Auth `_id` (ObjectId or string) and `id`. */
function buildUserLookupFilter(userId: string): Filter<UserDocument> {
  return isValidObjectId(userId)
    ? { $or: [{ _id: new ObjectId(userId) }, { _id: userId }, { id: userId }] }
    : { $or: [{ _id: userId }, { id: userId }] };
}

/** Normalizes user roles (treats legacy 'user' or missing role as 'customer'). */
function normalizeRole(rawRole?: string | null): UserRole {
  const normalized = rawRole?.toLowerCase().trim();
  if (normalized === 'admin') return 'admin';
  if (normalized === 'staff') return 'staff';
  return 'customer';
}

/** Validates and rounds positive currency amounts to 2 decimal places. */
function asPositiveAmount(value: unknown): number | null {
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return null;
  return Math.round(num * 100) / 100;
}

/** Escapes special regex characters before running MongoDB $regex searches. */
function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Rounds currency cleanly to 2 decimal places. */
function roundCurrency(value: number): number {
  return Math.round(value * 100) / 100;
}

/** Generates unique readable references for transactions & requests. */
function generateReference(prefix: string): string {
  const randomPart = crypto.randomBytes(4).toString('hex').toUpperCase();
  const timePart = Date.now().toString().slice(-6);
  return `${prefix}-${timePart}-${randomPart}`;
}

/** Generates a 12-digit Finova account number. */
function generateAccountNumber(): string {
  const digits = crypto.randomInt(100000000, 999999999).toString();
  return `901${digits}`;
}

/** Hashes a 4-6 digit transaction PIN with a unique salt using scrypt. */
function hashPin(pin: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

/** Constant-time PIN verification to prevent timing attacks. */
function verifyPin(pin: string, storedHash?: string): boolean {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, originalHex] = storedHash.split(':');
  const derivedBuffer = crypto.scryptSync(pin, salt, 64);
  const originalBuffer = Buffer.from(originalHex, 'hex');
  if (derivedBuffer.length !== originalBuffer.length) return false;
  return crypto.timingSafeEqual(derivedBuffer, originalBuffer);
}

/** Hashes a password using Better-Auth's exact scrypt parameters (`N:16384, r:16, p:1, dkLen:64`). */
function hashBetterAuthPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .scryptSync(password.normalize('NFKC'), salt, 64, {
      N: 16384,
      r: 16,
      p: 1,
      maxmem: 128 * 1024 * 1024,
    })
    .toString('hex');
  return `${salt}:${hash}`;
}

/** Simple rule-based suspicious transaction detector for Staff/Admin review. */
function evaluateSuspiciousActivity(
  amount: number,
  dailyTotalAfterTx: number,
  dailyLimit: number,
  alertThreshold: number
): { isSuspicious: boolean; reason?: string } {
  if (amount >= alertThreshold) {
    return { isSuspicious: true, reason: `High single transaction (>= ${alertThreshold})` };
  }
  if (dailyLimit > 0 && dailyTotalAfterTx >= dailyLimit * 0.9) {
    return { isSuspicious: true, reason: 'Reached 90%+ of daily transfer limit' };
  }
  return { isSuspicious: false };
}

/** Calculates fixed monthly EMI and builds an amortized repayment schedule. */
function buildRepaymentSchedule(
  principal: number,
  annualInterestRate: number,
  months: number
): { monthlyInstallment: number; schedule: LoanInstallment[] } {
  const monthlyRate = annualInterestRate / 12 / 100;
  const emi =
    monthlyRate === 0
      ? principal / months
      : (principal * monthlyRate * Math.pow(1 + monthlyRate, months)) /
        (Math.pow(1 + monthlyRate, months) - 1);

  const monthlyInstallment = roundCurrency(emi);
  const schedule: LoanInstallment[] = [];
  let remaining = principal;

  for (let i = 1; i <= months; i++) {
    const interest = roundCurrency(remaining * monthlyRate);
    const principalPart =
      i === months ? roundCurrency(remaining) : roundCurrency(monthlyInstallment - interest);
    const installmentAmount =
      i === months ? roundCurrency(principalPart + interest) : monthlyInstallment;
    remaining = Math.max(0, roundCurrency(remaining - principalPart));

    const dueDate = new Date();
    dueDate.setMonth(dueDate.getMonth() + i);

    schedule.push({
      installmentNumber: i,
      dueDate,
      amount: installmentAmount,
      principal: principalPart,
      interest,
      paidAmount: 0,
      status: 'Pending',
    });
  }

  return { monthlyInstallment, schedule };
}

// ============================================================================
// 4. DATABASE & BETTER-AUTH JWKS SETUP
// ============================================================================

function createMongoClient(): MongoClient {
  return new MongoClient(uri!, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
    serverSelectionTimeoutMS: 5000,
  });
}

let client = createMongoClient();

// Matches Better-Auth's `jwt()` plugin endpoint exposed by the Next.js app
const JWKS = createRemoteJWKSet(new URL(`${clientUrl}/api/auth/jwks`));

async function connectWithDnsFallback(): Promise<MongoClient> {
  try {
    await client.connect();
    return client;
  } catch (error: unknown) {
    const errMessage = error instanceof Error ? error.message : '';
    const errCode = (error as { code?: string })?.code || '';

    // Windows/ISP DNS resolvers sometimes fail SRV lookups for mongodb+srv:// URIs
    if (
      errMessage.includes('querySrv') ||
      errCode === 'ESERVFAIL' ||
      errCode === 'ECONNREFUSED'
    ) {
      console.warn(
        'Default DNS SRV lookup failed; retrying MongoDB connection via public DNS (8.8.8.8, 1.1.1.1)...'
      );
      dns.setServers(['8.8.8.8', '1.1.1.1']);
      client = createMongoClient();
      await client.connect();
      return client;
    }

    throw error;
  }
}

async function run() {
  try {
    console.log('Connecting to MongoDB...');
    await connectWithDnsFallback();
    await client.db(dbName).command({ ping: 1 });
    console.log(`Connected to MongoDB database: ${dbName}`);
    const db: Db = client.db(dbName);

    // Typed MongoDB Collections (shared "user" collection with Better-Auth)
    const usersCollection: Collection<UserDocument> = db.collection('user');
    const customerProfilesCollection: Collection<CustomerProfileDocument> =
      db.collection('customerProfiles');
    const accountsCollection: Collection<BankAccountDocument> = db.collection('bankAccounts');
    const accountRequestsCollection: Collection<AccountRequestDocument> =
      db.collection('accountRequests');
    const transactionsCollection: Collection<TransactionDocument> = db.collection('transactions');
    const requestsCollection: Collection<DepositWithdrawRequestDocument> =
      db.collection('depositWithdrawRequests');
    const loansCollection: Collection<LoanDocument> = db.collection('loans');
    const notificationsCollection: Collection<NotificationDocument> = db.collection('notifications');
    const settingsCollection: Collection<BankSettingsDocument> = db.collection('bankSettings');

    // Indexes for fast queries and duplicate prevention
    await Promise.all([
      customerProfilesCollection.createIndex({ userId: 1 }, { unique: true }),
      customerProfilesCollection.createIndex({ verificationStatus: 1, updatedAt: -1 }),
      accountsCollection.createIndex({ accountNumber: 1 }, { unique: true }),
      accountsCollection.createIndex({ userId: 1 }),
      accountRequestsCollection.createIndex({ userId: 1, createdAt: -1 }),
      transactionsCollection.createIndex({ transactionId: 1 }, { unique: true }),
      transactionsCollection.createIndex({ userId: 1, createdAt: -1 }),
      transactionsCollection.createIndex(
        { idempotencyKey: 1 },
        { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } }
      ),
      requestsCollection.createIndex(
        { idempotencyKey: 1 },
        { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } }
      ),
      loansCollection.createIndex({ userId: 1, createdAt: -1 }),
      notificationsCollection.createIndex({ userId: 1, createdAt: -1 }),
    ]);

    // Ensure default bank-wide settings document exists
    const existingSettings = await settingsCollection.findOne({ _id: 'global_limits' });
    if (!existingSettings) {
      await settingsCollection.insertOne({
        _id: 'global_limits',
        defaultDailyTransferLimit: 10000,
        defaultMaxSingleTransaction: 5000,
        defaultMinBalance: 50,
        largeTransactionAlertThreshold: 4000,
        transferFeePercent: 0,
        updatedAt: new Date(),
      });
    }

    async function getBankSettings(): Promise<BankSettingsDocument> {
      const settings = await settingsCollection.findOne({ _id: 'global_limits' });
      return (
        settings || {
          _id: 'global_limits',
          defaultDailyTransferLimit: 10000,
          defaultMaxSingleTransaction: 5000,
          defaultMinBalance: 50,
          largeTransactionAlertThreshold: 4000,
          transferFeePercent: 0,
          updatedAt: new Date(),
        }
      );
    }

    async function sendNotification(
      userId: string,
      title: string,
      message: string,
      type: NotificationDocument['type']
    ) {
      try {
        await notificationsCollection.insertOne({
          userId,
          title,
          message,
          type,
          isRead: false,
          createdAt: new Date(),
        });
      } catch (err) {
        console.error('Notification insert failed:', err);
      }
    }

    // ------------------------------------------------------------------------
    // AUTHENTICATION & ROLE-BASED ACCESS MIDDLEWARE
    // ------------------------------------------------------------------------

    /**
     * Verifies the Better-Auth JWT sent via `Authorization: Bearer <token>`
     * (from `authClient.token()`) or cookie fallback, then loads the user's
     * authoritative role and status from MongoDB.
     */
    const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
      if (req.method === 'OPTIONS') return next();

      const authHeader = req.headers.authorization;
      const token = authHeader?.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : req.cookies?.['better-auth.session_token'] ||
          req.cookies?.['__Secure-better-auth.session_token'];

      if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized: Missing token.' });
      }

      try {
        const { payload } = await jwtVerify(token, JWKS);
        const userId = payload.sub;

        if (!userId) {
          return res.status(401).json({ success: false, message: 'Invalid token payload.' });
        }

        const user = await usersCollection.findOne(buildUserLookupFilter(userId));

        if (!user) {
          return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const accountStatus: UserAccountStatus = user.status || 'active';
        if (accountStatus === 'blocked' || accountStatus === 'deactivated') {
          return res.status(403).json({
            success: false,
            message: `Account is ${accountStatus}. Please contact Finova support.`,
          });
        }

        const canonicalUserId = user._id?.toString() || userId;
        req.user = {
          ...payload,
          sub: canonicalUserId,
          id: canonicalUserId,
          role: normalizeRole(user.role),
          status: accountStatus,
        };

        next();
      } catch (error) {
        console.error('Token verification failed:', error);
        return res
          .status(403)
          .json({ success: false, message: 'Forbidden: Invalid or expired token.' });
      }
    };

    /** Enforces role-based authorization on the server. */
    const requireRole = (...allowedRoles: UserRole[]) => {
      return (req: Request, res: Response, next: NextFunction) => {
        const role = req.user?.role;
        if (!role || !allowedRoles.includes(role)) {
          return res.status(403).json({
            success: false,
            message: `Access denied. Required role: ${allowedRoles.join(' or ')}.`,
          });
        }
        next();
      };
    };

    // ========================================================================
    // 5. USER PROFILE, KYC VERIFICATION SUBMISSION, TRANSACTION PIN & ALERTS
    // ========================================================================

    // GET: Authenticated user's profile & KYC status (excludes sensitive hashes)
    app.get('/api/user/profile', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;

        const [user, pinDoc, customerProfile] = await Promise.all([
          usersCollection.findOne(buildUserLookupFilter(userId), {
            projection: { password: 0, transactionPinHash: 0, twoFactorChallenge: 0 },
          }),
          usersCollection.findOne(buildUserLookupFilter(userId), {
            projection: { transactionPinHash: 1 },
          }),
          customerProfilesCollection.findOne({ userId }),
        ]);

        if (!user) {
          return res.status(404).json({ success: false, message: 'User profile not found.' });
        }

        const derivedVerificationStatus: VerificationStatus =
          customerProfile?.verificationStatus ||
          user.verificationStatus ||
          (user.kycVerified ? 'verified' : 'incomplete');

        return res.status(200).json({
          success: true,
          user: {
            ...user,
            _id: user._id?.toString(),
            name: customerProfile?.fullName || user.name,
            phone: customerProfile?.phone || user.phone || '',
            dateOfBirth: customerProfile?.dateOfBirth || user.dateOfBirth || '',
            gender: customerProfile?.gender || user.gender || '',
            address: customerProfile?.address || user.address || '',
            city: customerProfile?.city || user.city || '',
            nationalId: customerProfile?.nationalId || user.nationalId || '',
            occupation: customerProfile?.occupation || user.occupation || '',
            employmentStatus: customerProfile?.employmentStatus || user.employmentStatus || '',
            monthlyIncome: customerProfile?.monthlyIncome ?? user.monthlyIncome,
            image: customerProfile?.profilePhotoUrl || user.image || '',
            nidDocumentUrl: customerProfile?.nidDocumentUrl || user.nidDocumentUrl || '',
            nidDocumentName: customerProfile?.nidDocumentName || '',
            supportingDocumentUrl:
              customerProfile?.supportingDocumentUrl || user.supportingDocumentUrl || '',
            supportingDocumentName: customerProfile?.supportingDocumentName || '',
            verificationNote: customerProfile?.verificationNote || user.verificationNote || '',
            role: normalizeRole(user.role),
            verificationStatus: derivedVerificationStatus,
            kycVerified: Boolean(user.kycVerified || derivedVerificationStatus === 'verified'),
            hasTransactionPin: Boolean(pinDoc?.transactionPinHash),
            twoFactorEnabled: Boolean(user.twoFactorEnabled),
          },
          customerProfile: customerProfile || null,
        });
      } catch (error) {
        console.error('Profile fetch error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PUT: Update own profile & optionally submit KYC details for Staff verification
    app.put('/api/user/profile', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const filter = buildUserLookupFilter(userId);
        const existingUser = await usersCollection.findOne(filter);

        if (!existingUser) {
          return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const existingProfile = await customerProfilesCollection.findOne({ userId });

        const name = asString(req.body.name);
        const image = asString(req.body.image);
        const phone = asString(req.body.phone);
        const address = asString(req.body.address);
        const city = asString(req.body.city);
        const dateOfBirth = asString(req.body.dateOfBirth);
        const gender = asString(req.body.gender);
        const nationalId = asString(req.body.nationalId);
        const occupation = asString(req.body.occupation);
        const employmentStatus = asString(req.body.employmentStatus);
        const nidDocumentUrl = asString(req.body.nidDocumentUrl);
        const nidDocumentName = asString(req.body.nidDocumentName);
        const supportingDocumentUrl = asString(req.body.supportingDocumentUrl);
        const supportingDocumentName = asString(req.body.supportingDocumentName);
        const submitForVerification = Boolean(req.body.submitForVerification);

        if (!isSafeUrl(image) || !isSafeUrl(nidDocumentUrl) || !isSafeUrl(supportingDocumentUrl)) {
          return res.status(400).json({
            success: false,
            message:
              'Invalid or oversized image/document. Use an http(s) URL or an image/PDF file under 500 KB.',
          });
        }

        const now = new Date();
        const updateFields: Partial<UserDocument> = { updatedAt: now };
        if (name) updateFields.name = name;
        if (image) updateFields.image = image;
        if (phone) updateFields.phone = phone;
        if (address) updateFields.address = address;
        if (city) updateFields.city = city;
        if (dateOfBirth) updateFields.dateOfBirth = dateOfBirth;
        if (gender) updateFields.gender = gender;
        if (nationalId) updateFields.nationalId = nationalId;
        if (occupation) updateFields.occupation = occupation;
        if (employmentStatus) updateFields.employmentStatus = employmentStatus;
        if (nidDocumentUrl) updateFields.nidDocumentUrl = nidDocumentUrl;
        if (supportingDocumentUrl) updateFields.supportingDocumentUrl = supportingDocumentUrl;

        let resolvedMonthlyIncome = existingProfile?.monthlyIncome ?? existingUser.monthlyIncome;
        if (req.body.monthlyIncome !== undefined && req.body.monthlyIncome !== '') {
          const income = Number(req.body.monthlyIncome);
          if (Number.isFinite(income) && income >= 0) {
            resolvedMonthlyIncome = roundCurrency(income);
            updateFields.monthlyIncome = resolvedMonthlyIncome;
          }
        }

        const effectiveName = name || existingProfile?.fullName || existingUser.name || '';
        const effectivePhone = phone || existingProfile?.phone || existingUser.phone || '';
        const effectiveDob =
          dateOfBirth || existingProfile?.dateOfBirth || existingUser.dateOfBirth || '';
        const effectiveGender = gender || existingProfile?.gender || existingUser.gender || '';
        const effectiveAddress = address || existingProfile?.address || existingUser.address || '';
        const effectiveCity = city || existingProfile?.city || existingUser.city || '';
        const effectiveNationalId =
          nationalId || existingProfile?.nationalId || existingUser.nationalId || '';
        const effectiveOccupation =
          occupation || existingProfile?.occupation || existingUser.occupation || '';
        const effectiveNidDoc =
          nidDocumentUrl || existingProfile?.nidDocumentUrl || existingUser.nidDocumentUrl || '';
        const effectiveSupportingDoc =
          supportingDocumentUrl ||
          existingProfile?.supportingDocumentUrl ||
          existingUser.supportingDocumentUrl ||
          '';

        let nextStatus: VerificationStatus =
          existingProfile?.verificationStatus ||
          existingUser.verificationStatus ||
          (existingUser.kycVerified ? 'verified' : 'incomplete');

        if (submitForVerification) {
          const missing: string[] = [];
          if (!effectiveName) missing.push('Full Name');
          if (!effectivePhone) missing.push('Phone');
          if (!effectiveDob) missing.push('Date of Birth');
          if (!effectiveGender) missing.push('Gender');
          if (!effectiveAddress) missing.push('Address');
          if (!effectiveCity) missing.push('City');
          if (!effectiveNationalId) missing.push('National ID');
          if (!effectiveOccupation) missing.push('Occupation');
          if (!effectiveNidDoc) missing.push('NID Document');

          if (missing.length > 0) {
            return res.status(400).json({
              success: false,
              message: `Please complete all required verification fields: ${missing.join(', ')}.`,
            });
          }

          nextStatus = 'pending';
          updateFields.verificationStatus = 'pending';
          updateFields.kycVerified = false;
          updateFields.verificationNote = '';
        } else if (!existingUser.verificationStatus) {
          updateFields.verificationStatus = nextStatus;
        }

        const profileSetFields: Partial<CustomerProfileDocument> = {
          userId,
          fullName: effectiveName,
          email: existingUser.email || existingProfile?.email || '',
          phone: effectivePhone,
          dateOfBirth: effectiveDob,
          gender: effectiveGender,
          address: effectiveAddress,
          city: effectiveCity,
          nationalId: effectiveNationalId,
          occupation: effectiveOccupation,
          employmentStatus:
            employmentStatus || existingProfile?.employmentStatus || existingUser.employmentStatus || '',
          monthlyIncome: resolvedMonthlyIncome,
          profilePhotoUrl: image || existingProfile?.profilePhotoUrl || existingUser.image || '',
          nidDocumentUrl: effectiveNidDoc,
          nidDocumentName: nidDocumentName || existingProfile?.nidDocumentName || '',
          supportingDocumentUrl: effectiveSupportingDoc,
          supportingDocumentName:
            supportingDocumentName || existingProfile?.supportingDocumentName || '',
          verificationStatus: nextStatus,
          verificationNote: submitForVerification ? '' : existingProfile?.verificationNote || '',
          updatedAt: now,
          ...(submitForVerification ? { submittedAt: now } : {}),
        };

        await Promise.all([
          usersCollection.updateOne(filter, { $set: updateFields }),
          customerProfilesCollection.updateOne(
            { userId },
            {
              $set: profileSetFields,
              $setOnInsert: { createdAt: now },
            },
            { upsert: true }
          ),
        ]);

        if (submitForVerification) {
          await sendNotification(
            userId,
            'KYC Profile Submitted',
            'Your personal details and identity documents have been submitted and are now pending Staff verification.',
            'kyc'
          );
        }

        return res.status(200).json({
          success: true,
          verificationStatus: nextStatus,
          message: submitForVerification
            ? 'Profile submitted for Staff verification.'
            : 'Profile draft saved successfully.',
        });
      } catch (error) {
        console.error('Profile update error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PUT: Set or change 4-6 digit Transaction PIN (stored hashed with scrypt)
    app.put('/api/user/transaction-pin', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const filter = buildUserLookupFilter(userId);

        const currentPin = asString(req.body.currentPin);
        const newPin = asString(req.body.newPin);

        if (!/^\d{4,6}$/.test(newPin)) {
          return res.status(400).json({
            success: false,
            message: 'Transaction PIN must be 4 to 6 numeric digits.',
          });
        }

        const user = await usersCollection.findOne(filter);
        if (!user) {
          return res.status(404).json({ success: false, message: 'User not found.' });
        }

        if (user.transactionPinHash && !verifyPin(currentPin, user.transactionPinHash)) {
          return res.status(403).json({
            success: false,
            message: 'Current transaction PIN is incorrect.',
          });
        }

        await usersCollection.updateOne(filter, {
          $set: { transactionPinHash: hashPin(newPin), updatedAt: new Date() },
        });

        return res
          .status(200)
          .json({ success: true, message: 'Transaction PIN updated securely.' });
      } catch (error) {
        console.error('PIN update error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    async function verifyTwoFactorIfEnabled(
      userDoc: UserDocument | null,
      code: string,
      filter: Filter<UserDocument>
    ): Promise<{ ok: true } | { ok: false; status: number; message: string }> {
      if (!userDoc?.twoFactorEnabled) return { ok: true };

      if (!/^\d{6}$/.test(code)) {
        return {
          ok: false,
          status: 400,
          message: 'A 6-digit 2FA verification code is required.',
        };
      }

      const challenge = userDoc.twoFactorChallenge;
      if (!challenge || !challenge.codeHash || new Date() > new Date(challenge.expiresAt)) {
        return {
          ok: false,
          status: 403,
          message: '2FA verification code has expired or was not requested. Request a new code.',
        };
      }

      if (!verifyPin(code, challenge.codeHash)) {
        return { ok: false, status: 403, message: 'Invalid 2FA verification code.' };
      }

      await usersCollection.updateOne(filter, {
        $set: { twoFactorChallenge: null, updatedAt: new Date() },
      });
      return { ok: true };
    }

    // PUT: Enable or disable Two-Factor Authentication (requires Transaction PIN)
    app.put('/api/user/2fa', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const filter = buildUserLookupFilter(userId);
        const enabled = Boolean(req.body.enabled);
        const transactionPin = asString(req.body.transactionPin);

        const user = await usersCollection.findOne(filter);
        if (!user) {
          return res.status(404).json({ success: false, message: 'User not found.' });
        }

        if (!user.transactionPinHash) {
          return res.status(400).json({
            success: false,
            message: 'Please set a Transaction PIN before configuring Two-Factor Authentication.',
          });
        }

        if (!transactionPin || !verifyPin(transactionPin, user.transactionPinHash)) {
          return res.status(403).json({
            success: false,
            message: 'Valid Transaction PIN is required to change 2FA settings.',
          });
        }

        await usersCollection.updateOne(filter, {
          $set: {
            twoFactorEnabled: enabled,
            twoFactorChallenge: null,
            updatedAt: new Date(),
          },
        });

        await sendNotification(
          userId,
          enabled ? '2FA Enabled' : '2FA Disabled',
          enabled
            ? 'Two-Factor Authentication is now active on transfers, withdrawals, and loan repayments.'
            : 'Two-Factor Authentication was disabled on your account.',
          'security'
        );

        return res.status(200).json({
          success: true,
          twoFactorEnabled: enabled,
          message: enabled
            ? 'Two-Factor Authentication enabled.'
            : 'Two-Factor Authentication disabled.',
        });
      } catch (error) {
        console.error('2FA toggle error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // POST: Generate & dispatch a 6-digit 2FA OTP via secure hash + in-app notification
    app.post('/api/user/2fa/send-code', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const filter = buildUserLookupFilter(userId);
        const purpose = asString(req.body.purpose) || 'sensitive transaction';

        const user = await usersCollection.findOne(filter);
        if (!user) {
          return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        await usersCollection.updateOne(filter, {
          $set: {
            twoFactorChallenge: {
              codeHash: hashPin(otp),
              purpose,
              expiresAt,
            },
            updatedAt: new Date(),
          },
        });

        await sendNotification(
          userId,
          '2FA Security Code',
          `Your 6-digit verification code for ${purpose} is ${otp}. Valid for 5 minutes.`,
          'security'
        );

        return res.status(200).json({
          success: true,
          message: '6-digit verification code generated and sent to your notifications.',
          expiresInSeconds: 300,
          demoOtp: otp,
        });
      } catch (error) {
        console.error('2FA send-code error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // GET: Fetch notifications for Navbar bell & dashboard
    app.get('/api/notifications', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const [notifications, unreadCount] = await Promise.all([
          notificationsCollection.find({ userId }).sort({ createdAt: -1 }).limit(30).toArray(),
          notificationsCollection.countDocuments({ userId, isRead: false }),
        ]);

        return res.status(200).json({ success: true, unreadCount, data: notifications });
      } catch (error) {
        console.error('Error fetching notifications:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PATCH: Mark a single notification (or "all") as read
    app.patch('/api/notifications/:id/read', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;
        const id = getParam(req.params.id);

        if (id === 'all') {
          await notificationsCollection.updateMany(
            { userId, isRead: false },
            { $set: { isRead: true } }
          );
          return res
            .status(200)
            .json({ success: true, message: 'All notifications marked as read.' });
        }

        if (!isValidObjectId(id)) {
          return res.status(400).json({ success: false, message: 'Invalid notification ID.' });
        }

        const result = await notificationsCollection.updateOne(
          { _id: new ObjectId(id), userId },
          { $set: { isRead: true } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ success: false, message: 'Notification not found.' });
        }

        return res.status(200).json({ success: true, message: 'Notification marked as read.' });
      } catch (error) {
        console.error('Error updating notification:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // ========================================================================
    // 6. BANK ACCOUNTS & CUSTOMER ACCOUNT APPLICATION WORKFLOW
    // ========================================================================

    // GET: List bank accounts (Customers see ONLY their own; Admin & Staff see all)
    app.get('/api/accounts', verifyToken, async (req: Request, res: Response) => {
      try {
        const { role, id: currentUserId } = req.user!;
        const search = asString(req.query.search);
        const status = asString(req.query.status);
        const accountType = asString(req.query.accountType);

        const filter: Record<string, unknown> = {};

        if (role === 'customer') {
          filter.userId = currentUserId;
        } else if (asString(req.query.userId)) {
          filter.userId = asString(req.query.userId);
        }

        if (status && ['Active', 'Frozen', 'Closed'].includes(status)) filter.status = status;
        if (accountType && ['Savings', 'Current', 'Business'].includes(accountType)) {
          filter.accountType = accountType;
        }
        if (search) {
          filter.accountNumber = { $regex: escapeRegex(search), $options: 'i' };
        }

        const accounts = await accountsCollection.find(filter).sort({ createdAt: -1 }).toArray();
        return res.status(200).json({ success: true, count: accounts.length, data: accounts });
      } catch (error) {
        console.error('Error fetching bank accounts:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // GET: Single bank account details (with ownership check)
    app.get('/api/accounts/:id', verifyToken, async (req: Request, res: Response) => {
      try {
        const id = getParam(req.params.id);
        if (!isValidObjectId(id)) {
          return res.status(400).json({ success: false, message: 'Invalid account ID.' });
        }

        const account = await accountsCollection.findOne({ _id: new ObjectId(id) });
        if (!account) {
          return res.status(404).json({ success: false, message: 'Bank account not found.' });
        }

        if (req.user!.role === 'customer' && account.userId !== req.user!.id) {
          return res.status(403).json({ success: false, message: 'Access denied.' });
        }

        return res.status(200).json({ success: true, data: account });
      } catch (error) {
        console.error('Error fetching account:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // POST: Create a new bank account for a verified customer (Admin or Bank Staff)
    app.post(
      '/api/accounts',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const targetUserId = asString(req.body.userId);
          const accountType = asString(req.body.accountType) as BankAccountType;
          const initialDeposit = req.body.initialDeposit
            ? asPositiveAmount(req.body.initialDeposit)
            : 0;

          if (!targetUserId || !['Savings', 'Current', 'Business'].includes(accountType)) {
            return res.status(400).json({
              success: false,
              message: 'Valid userId and accountType (Savings, Current, Business) are required.',
            });
          }

          if (req.body.initialDeposit && initialDeposit === null) {
            return res.status(400).json({ success: false, message: 'Invalid initial deposit amount.' });
          }

          const customer = await usersCollection.findOne(buildUserLookupFilter(targetUserId));
          if (!customer) {
            return res.status(404).json({ success: false, message: 'Customer not found.' });
          }

          // Enforce KYC verification before opening a bank account (Step 4 -> Step 5)
          const isVerified = Boolean(
            customer.kycVerified || customer.verificationStatus === 'verified'
          );
          if (!isVerified) {
            return res.status(400).json({
              success: false,
              message:
                'Customer profile must be KYC verified before a bank account can be opened.',
            });
          }

          const settings = await getBankSettings();
          const canonicalCustomerId = customer._id?.toString() || targetUserId;

          const newAccount: BankAccountDocument = {
            userId: canonicalCustomerId,
            accountNumber: generateAccountNumber(),
            accountType,
            balance: initialDeposit || 0,
            status: 'Active',
            dailyTransferLimit: settings.defaultDailyTransferLimit,
            maxSingleTransaction: settings.defaultMaxSingleTransaction,
            minBalance: settings.defaultMinBalance,
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await accountsCollection.insertOne(newAccount);

          if (initialDeposit && initialDeposit > 0) {
            await transactionsCollection.insertOne({
              transactionId: generateReference('TXN'),
              userId: canonicalCustomerId,
              receiverAccountId: result.insertedId.toString(),
              receiverAccountNumber: newAccount.accountNumber,
              type: 'Deposit',
              amount: initialDeposit,
              fee: 0,
              status: 'Completed',
              description: `Initial opening deposit (${accountType} Account)`,
              isSuspicious: false,
              reviewedBy: req.user!.id,
              createdAt: new Date(),
            });
          }

          await sendNotification(
            canonicalCustomerId,
            'New Bank Account Opened',
            `Your ${accountType} account (${newAccount.accountNumber}) is now active.`,
            'account'
          );

          return res.status(201).json({
            success: true,
            message: 'Bank account created successfully.',
            data: { ...newAccount, _id: result.insertedId },
          });
        } catch (error) {
          console.error('Error creating account:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // PATCH: Freeze/unfreeze account, update type, or set limits (Admin only)
    app.patch(
      '/api/accounts/:id',
      verifyToken,
      requireRole('admin'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid account ID.' });
          }

          const existing = await accountsCollection.findOne({ _id: new ObjectId(id) });
          if (!existing) {
            return res.status(404).json({ success: false, message: 'Bank account not found.' });
          }

          const updates: Partial<BankAccountDocument> = { updatedAt: new Date() };
          const status = asString(req.body.status) as BankAccountStatus;
          const accountType = asString(req.body.accountType) as BankAccountType;

          if (status) {
            if (!['Active', 'Frozen', 'Closed'].includes(status)) {
              return res.status(400).json({ success: false, message: 'Invalid account status.' });
            }
            updates.status = status;
          }

          if (accountType) {
            if (!['Savings', 'Current', 'Business'].includes(accountType)) {
              return res.status(400).json({ success: false, message: 'Invalid account type.' });
            }
            updates.accountType = accountType;
          }

          if (req.body.dailyTransferLimit !== undefined) {
            const val = asPositiveAmount(req.body.dailyTransferLimit);
            if (val === null)
              return res.status(400).json({ success: false, message: 'Invalid daily limit.' });
            updates.dailyTransferLimit = val;
          }
          if (req.body.maxSingleTransaction !== undefined) {
            const val = asPositiveAmount(req.body.maxSingleTransaction);
            if (val === null)
              return res
                .status(400)
                .json({ success: false, message: 'Invalid max single limit.' });
            updates.maxSingleTransaction = val;
          }
          if (req.body.minBalance !== undefined) {
            const num = Number(req.body.minBalance);
            if (!Number.isFinite(num) || num < 0) {
              return res
                .status(400)
                .json({ success: false, message: 'Invalid minimum balance.' });
            }
            updates.minBalance = roundCurrency(num);
          }

          await accountsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updates });

          if (status && status !== existing.status) {
            await sendNotification(
              existing.userId,
              `Bank Account ${status}`,
              `Your ${existing.accountType} account (${existing.accountNumber}) status changed to ${status}.`,
              'security'
            );
          }

          return res
            .status(200)
            .json({ success: true, message: 'Bank account updated successfully.' });
        } catch (error) {
          console.error('Error updating account:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // POST: Customer requests a new bank account (Step 5)
    app.post(
      '/api/account-requests',
      verifyToken,
      requireRole('customer'),
      async (req: Request, res: Response) => {
        try {
          const userId = req.user!.id;
          const accountType = asString(req.body.accountType) as BankAccountType;
          const purpose = asString(req.body.purpose) || `${accountType} banking account`;

          if (!['Savings', 'Current', 'Business'].includes(accountType)) {
            return res.status(400).json({
              success: false,
              message: 'Valid accountType (Savings, Current, Business) is required.',
            });
          }

          const user = await usersCollection.findOne(buildUserLookupFilter(userId));
          const isVerified = Boolean(
            user?.kycVerified || user?.verificationStatus === 'verified'
          );
          if (!isVerified) {
            return res.status(400).json({
              success: false,
              message: 'Complete and verify your KYC profile before applying for a bank account.',
            });
          }

          const newReq: AccountRequestDocument = {
            requestCode: generateReference('AREQ'),
            userId,
            accountType,
            purpose,
            status: 'Pending',
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await accountRequestsCollection.insertOne(newReq);

          return res.status(201).json({
            success: true,
            message: 'Bank account application submitted for Staff review.',
            data: { ...newReq, _id: result.insertedId },
          });
        } catch (error) {
          console.error('Account request creation error:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // GET: List bank account requests (Customer sees own; Staff/Admin see all)
    app.get('/api/account-requests', verifyToken, async (req: Request, res: Response) => {
      try {
        const filter: Record<string, unknown> = {};
        if (req.user!.role === 'customer') {
          filter.userId = req.user!.id;
        }
        const status = asString(req.query.status);
        if (status && ['Pending', 'Approved', 'Rejected'].includes(status)) {
          filter.status = status;
        }

        const list = await accountRequestsCollection
          .find(filter)
          .sort({ createdAt: -1 })
          .toArray();
        return res.status(200).json({ success: true, count: list.length, data: list });
      } catch (error) {
        console.error('Error fetching account requests:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PATCH: Staff or Admin approves/rejects a customer's bank account request
    app.patch(
      '/api/account-requests/:id/review',
      verifyToken,
      requireRole('staff', 'admin'),
      async (req: Request, res: Response) => {
        const session = client.startSession();
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid request ID.' });
          }

          const decision = asString(req.body.decision) as 'Approved' | 'Rejected';
          const reviewNote = asString(req.body.reviewNote);

          if (!['Approved', 'Rejected'].includes(decision)) {
            return res
              .status(400)
              .json({ success: false, message: 'Decision must be Approved or Rejected.' });
          }

          let targetUserId = '';
          let createdAccNumber = '';
          let createdAccType: BankAccountType = 'Savings';

          await session.withTransaction(async () => {
            const accReq = await accountRequestsCollection.findOne(
              { _id: new ObjectId(id) },
              { session }
            );
            if (!accReq) throw new Error('HTTP_404:Account request not found.');
            if (accReq.status !== 'Pending') {
              throw new Error(`HTTP_400:Account request is already ${accReq.status}.`);
            }

            targetUserId = accReq.userId;
            createdAccType = accReq.accountType;

            if (decision === 'Rejected') {
              await accountRequestsCollection.updateOne(
                { _id: accReq._id },
                {
                  $set: {
                    status: 'Rejected',
                    reviewedBy: req.user!.id,
                    reviewNote,
                    updatedAt: new Date(),
                  },
                },
                { session }
              );
              return;
            }

            const customer = await usersCollection.findOne(buildUserLookupFilter(accReq.userId), {
              session,
            });
            const isVerified = Boolean(
              customer?.kycVerified || customer?.verificationStatus === 'verified'
            );
            if (!isVerified) {
              throw new Error('HTTP_400:Customer KYC profile must be verified before approval.');
            }

            const settings = await getBankSettings();
            createdAccNumber = generateAccountNumber();

            const newAccount: BankAccountDocument = {
              userId: accReq.userId,
              accountNumber: createdAccNumber,
              accountType: accReq.accountType,
              balance: 0,
              status: 'Active',
              dailyTransferLimit: settings.defaultDailyTransferLimit,
              maxSingleTransaction: settings.defaultMaxSingleTransaction,
              minBalance: settings.defaultMinBalance,
              createdAt: new Date(),
              updatedAt: new Date(),
            };

            const insertResult = await accountsCollection.insertOne(newAccount, { session });

            await accountRequestsCollection.updateOne(
              { _id: accReq._id },
              {
                $set: {
                  status: 'Approved',
                  reviewedBy: req.user!.id,
                  reviewNote,
                  createdAccountId: insertResult.insertedId.toString(),
                  createdAccountNumber: createdAccNumber,
                  updatedAt: new Date(),
                },
              },
              { session }
            );
          });

          if (targetUserId) {
            await sendNotification(
              targetUserId,
              `Bank Account Application ${decision}`,
              decision === 'Approved'
                ? `Your ${createdAccType} account (${createdAccNumber}) has been opened and is now active.`
                : `Your ${createdAccType} account application was declined.${
                    reviewNote ? ` Note: ${reviewNote}` : ''
                  }`,
              'account'
            );
          }

          return res.status(200).json({
            success: true,
            message:
              decision === 'Approved'
                ? `Account ${createdAccNumber} opened successfully.`
                : 'Account application rejected.',
          });
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Review failed.';
          if (message.startsWith('HTTP_')) {
            const [codePart, ...rest] = message.split(':');
            return res.status(Number(codePart.replace('HTTP_', '')) || 400).json({
              success: false,
              message: rest.join(':'),
            });
          }
          console.error('Error reviewing account request:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        } finally {
          await session.endSession();
        }
      }
    );

    // ========================================================================
    // 7. ATOMIC FUND TRANSFERS (Customer -> Own Account or Another Customer)
    // ========================================================================

    app.post(
      '/api/transfers',
      verifyToken,
      requireRole('customer'),
      async (req: Request, res: Response) => {
        const session = client.startSession();
        try {
          const senderUserId = req.user!.id;
          const senderAccountId = asString(req.body.senderAccountId);
          const recipientAccountNumber = asString(req.body.recipientAccountNumber);
          const amount = asPositiveAmount(req.body.amount);
          const description = asString(req.body.description) || 'Fund Transfer';
          const transactionPin = asString(req.body.transactionPin);
          const idempotencyKey =
            getParam(req.headers['idempotency-key']) || asString(req.body.idempotencyKey);

          if (!isValidObjectId(senderAccountId) || !recipientAccountNumber || amount === null) {
            return res.status(400).json({
              success: false,
              message:
                'Valid senderAccountId, recipientAccountNumber, and positive amount are required.',
            });
          }

          if (!transactionPin) {
            return res.status(400).json({ success: false, message: 'Transaction PIN is required.' });
          }

          if (idempotencyKey) {
            const duplicate = await transactionsCollection.findOne({ idempotencyKey });
            if (duplicate) {
              return res.status(200).json({
                success: true,
                message: 'Transfer already processed.',
                data: duplicate,
              });
            }
          }

          const senderUser = await usersCollection.findOne(buildUserLookupFilter(senderUserId));
          if (!senderUser?.transactionPinHash) {
            return res.status(400).json({
              success: false,
              message: 'Please set a Transaction PIN in your profile before transferring funds.',
            });
          }
          if (!verifyPin(transactionPin, senderUser.transactionPinHash)) {
            return res.status(403).json({ success: false, message: 'Invalid Transaction PIN.' });
          }

          const twoFactorCheck = await verifyTwoFactorIfEnabled(
            senderUser,
            asString(req.body.twoFactorCode),
            buildUserLookupFilter(senderUserId)
          );
          if (!twoFactorCheck.ok) {
            return res.status(twoFactorCheck.status).json({
              success: false,
              message: twoFactorCheck.message,
            });
          }

          const settings = await getBankSettings();
          const fee = roundCurrency((amount * settings.transferFeePercent) / 100);
          const totalDebit = roundCurrency(amount + fee);

          let createdTransaction: TransactionDocument | null = null;
          let receiverUserId = '';
          let senderAccNumber = '';
          let senderBalanceAfter = 0;

          // Atomic MongoDB transaction ensures sender debit and receiver credit succeed or fail together
          await session.withTransaction(async () => {
            const senderAccount = await accountsCollection.findOne(
              { _id: new ObjectId(senderAccountId), userId: senderUserId },
              { session }
            );

            if (!senderAccount) {
              throw new Error('HTTP_404:Sender account not found or does not belong to you.');
            }
            if (senderAccount.status !== 'Active') {
              throw new Error(`HTTP_400:Sender account is ${senderAccount.status}.`);
            }
            if (senderAccount.accountNumber === recipientAccountNumber) {
              throw new Error('HTTP_400:Cannot transfer funds to the same account.');
            }

            const receiverAccount = await accountsCollection.findOne(
              { accountNumber: recipientAccountNumber },
              { session }
            );
            if (!receiverAccount) {
              throw new Error('HTTP_404:Recipient account number not found.');
            }
            if (receiverAccount.status !== 'Active') {
              throw new Error(`HTTP_400:Recipient account is ${receiverAccount.status}.`);
            }

            const receiverOwner = await usersCollection.findOne(
              buildUserLookupFilter(receiverAccount.userId),
              { session, projection: { status: 1 } }
            );
            if (receiverOwner?.status && receiverOwner.status !== 'active') {
              throw new Error(
                `HTTP_403:Recipient customer is ${receiverOwner.status} and cannot receive funds.`
              );
            }

            if (amount > senderAccount.maxSingleTransaction) {
              throw new Error(
                `HTTP_400:Amount exceeds single transaction limit of ${senderAccount.maxSingleTransaction}.`
              );
            }
            if (senderAccount.balance - totalDebit < senderAccount.minBalance) {
              throw new Error(
                'HTTP_400:Insufficient balance (respecting minimum balance requirement).'
              );
            }

            const startOfDay = new Date();
            startOfDay.setHours(0, 0, 0, 0);
            const dailyStats = await transactionsCollection
              .aggregate(
                [
                  {
                    $match: {
                      senderAccountId: senderAccount._id!.toString(),
                      type: 'Fund Transfer',
                      status: 'Completed',
                      createdAt: { $gte: startOfDay },
                    },
                  },
                  { $group: { _id: null, totalToday: { $sum: '$amount' } } },
                ],
                { session }
              )
              .toArray();

            const transferredToday = dailyStats[0]?.totalToday || 0;
            if (transferredToday + amount > senderAccount.dailyTransferLimit) {
              throw new Error(
                `HTTP_400:Daily transfer limit of ${senderAccount.dailyTransferLimit} exceeded.`
              );
            }

            const debitResult = await accountsCollection.updateOne(
              {
                _id: senderAccount._id,
                status: 'Active',
                balance: { $gte: roundCurrency(totalDebit + senderAccount.minBalance) },
              },
              { $inc: { balance: -totalDebit }, $set: { updatedAt: new Date() } },
              { session }
            );

            if (debitResult.modifiedCount !== 1) {
              throw new Error(
                'HTTP_409:Transfer could not be completed due to concurrent balance change.'
              );
            }

            await accountsCollection.updateOne(
              { _id: receiverAccount._id, status: 'Active' },
              { $inc: { balance: amount }, $set: { updatedAt: new Date() } },
              { session }
            );

            const suspiciousCheck = evaluateSuspiciousActivity(
              amount,
              transferredToday + amount,
              senderAccount.dailyTransferLimit,
              settings.largeTransactionAlertThreshold
            );

            const txDoc: TransactionDocument = {
              transactionId: generateReference('TXN'),
              ...(idempotencyKey ? { idempotencyKey } : {}),
              userId: senderUserId,
              receiverUserId: receiverAccount.userId,
              senderAccountId: senderAccount._id!.toString(),
              senderAccountNumber: senderAccount.accountNumber,
              receiverAccountId: receiverAccount._id!.toString(),
              receiverAccountNumber: receiverAccount.accountNumber,
              type: 'Fund Transfer',
              amount,
              fee,
              status: 'Completed',
              description,
              isSuspicious: suspiciousCheck.isSuspicious,
              ...(suspiciousCheck.reason ? { suspiciousReason: suspiciousCheck.reason } : {}),
              createdAt: new Date(),
            };

            await transactionsCollection.insertOne(txDoc, { session });

            createdTransaction = txDoc;
            receiverUserId = receiverAccount.userId;
            senderAccNumber = senderAccount.accountNumber;
            senderBalanceAfter = roundCurrency(senderAccount.balance - totalDebit);
          });

          let receiverName = 'Finova Customer';
          if (createdTransaction) {
            const receiverUser = receiverUserId
              ? await usersCollection.findOne(buildUserLookupFilter(receiverUserId), {
                  projection: { name: 1 },
                })
              : null;
            receiverName = receiverUser?.name || 'Finova Customer';

            const txRef = (createdTransaction as TransactionDocument).transactionId;
            await Promise.all([
              sendNotification(
                senderUserId,
                'Transfer Completed',
                `You sent ${amount} from ${senderAccNumber} to ${recipientAccountNumber}. Ref: ${txRef}`,
                'transfer'
              ),
              receiverUserId !== senderUserId
                ? sendNotification(
                    receiverUserId,
                    'Money Received',
                    `You received ${amount} into ${recipientAccountNumber} from ${senderAccNumber}. Ref: ${txRef}`,
                    'transfer'
                  )
                : Promise.resolve(),
            ]);
          }

          return res.status(201).json({
            success: true,
            message: 'Fund transfer completed successfully.',
            data: createdTransaction
              ? {
                  ...(createdTransaction as TransactionDocument),
                  senderName: senderUser.name || 'Customer',
                  receiverName,
                  senderBalanceAfter,
                }
              : null,
          });
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Transfer failed.';
          if (message.startsWith('HTTP_')) {
            const [codePart, ...rest] = message.split(':');
            return res.status(Number(codePart.replace('HTTP_', '')) || 400).json({
              success: false,
              message: rest.join(':'),
            });
          }
          console.error('Atomic transfer error:', error);
          return res.status(500).json({
            success: false,
            message: 'Transfer failed and was safely rolled back.',
          });
        } finally {
          await session.endSession();
        }
      }
    );

    // ========================================================================
    // 8. DEPOSIT & WITHDRAWAL REQUEST WORKFLOW (Staff Review -> Admin Approval)
    // ========================================================================

    // POST: Customer submits a Deposit or Withdrawal request
    app.post(
      '/api/requests',
      verifyToken,
      requireRole('customer'),
      async (req: Request, res: Response) => {
        try {
          const userId = req.user!.id;
          const accountId = asString(req.body.accountId);
          const type = asString(req.body.type) as 'Deposit' | 'Withdrawal';
          const amount = asPositiveAmount(req.body.amount);
          const description = asString(req.body.description) || `${type} request`;
          const idempotencyKey =
            getParam(req.headers['idempotency-key']) || asString(req.body.idempotencyKey);

          if (
            !isValidObjectId(accountId) ||
            !['Deposit', 'Withdrawal'].includes(type) ||
            amount === null
          ) {
            return res.status(400).json({
              success: false,
              message: 'Valid accountId, type (Deposit/Withdrawal), and positive amount are required.',
            });
          }

          if (idempotencyKey) {
            const existingRequest = await requestsCollection.findOne({ idempotencyKey, userId });
            if (existingRequest) {
              return res.status(200).json({
                success: true,
                message: `${type} request already submitted.`,
                data: existingRequest,
              });
            }
          }

          const account = await accountsCollection.findOne({
            _id: new ObjectId(accountId),
            userId,
          });
          if (!account) {
            return res
              .status(404)
              .json({ success: false, message: 'Account not found or access denied.' });
          }
          if (account.status !== 'Active') {
            return res.status(400).json({ success: false, message: `Account is ${account.status}.` });
          }

          if (type === 'Withdrawal' && account.balance - amount < account.minBalance) {
            return res.status(400).json({
              success: false,
              message: 'Insufficient available balance for this withdrawal request.',
            });
          }

          if (type === 'Withdrawal') {
            const reqUser = await usersCollection.findOne(buildUserLookupFilter(userId));
            const twoFactorCheck = await verifyTwoFactorIfEnabled(
              reqUser,
              asString(req.body.twoFactorCode),
              buildUserLookupFilter(userId)
            );
            if (!twoFactorCheck.ok) {
              return res.status(twoFactorCheck.status).json({
                success: false,
                message: twoFactorCheck.message,
              });
            }
          }

          const newRequest: DepositWithdrawRequestDocument = {
            requestCode: generateReference(type === 'Deposit' ? 'DEP' : 'WDR'),
            ...(idempotencyKey ? { idempotencyKey } : {}),
            userId,
            accountId: account._id!.toString(),
            accountNumber: account.accountNumber,
            type,
            amount,
            description,
            status: 'Pending',
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await requestsCollection.insertOne(newRequest);

          return res.status(201).json({
            success: true,
            message: `${type} request submitted and is pending review.`,
            data: { ...newRequest, _id: result.insertedId },
          });
        } catch (error) {
          console.error('Error creating deposit/withdraw request:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // GET: List Deposit/Withdrawal requests (Customers see own; Staff/Admin see all)
    app.get('/api/requests', verifyToken, async (req: Request, res: Response) => {
      try {
        const filter: Record<string, unknown> = {};
        if (req.user!.role === 'customer') {
          filter.userId = req.user!.id;
        }
        const status = asString(req.query.status);
        const type = asString(req.query.type);
        if (status && ['Pending', 'Under Review', 'Approved', 'Rejected'].includes(status)) {
          filter.status = status;
        }
        if (type && ['Deposit', 'Withdrawal'].includes(type)) filter.type = type;

        const requests = await requestsCollection.find(filter).sort({ createdAt: -1 }).toArray();
        return res.status(200).json({ success: true, count: requests.length, data: requests });
      } catch (error) {
        console.error('Error fetching requests:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PATCH: Staff reviews & forwards a Deposit/Withdrawal request to Admin
    app.patch(
      '/api/requests/:id/staff-review',
      verifyToken,
      requireRole('staff', 'admin'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid request ID.' });
          }

          const staffNote = asString(req.body.staffNote) || asString(req.body.reviewNote);
          const forwardToAdmin =
            req.body.forwardToAdmin === undefined ? true : Boolean(req.body.forwardToAdmin);

          const requestDoc = await requestsCollection.findOne({ _id: new ObjectId(id) });
          if (!requestDoc) {
            return res.status(404).json({ success: false, message: 'Request not found.' });
          }
          if (requestDoc.userId === req.user!.id) {
            return res
              .status(403)
              .json({ success: false, message: 'Cannot review your own request.' });
          }
          if (!['Pending', 'Under Review'].includes(requestDoc.status)) {
            return res
              .status(400)
              .json({ success: false, message: `Request is already ${requestDoc.status}.` });
          }

          await requestsCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                ...(forwardToAdmin && requestDoc.status === 'Pending'
                  ? { status: 'Under Review' as const, forwardedByStaffId: req.user!.id }
                  : {}),
                ...(staffNote ? { staffNote } : {}),
                updatedAt: new Date(),
              },
            }
          );

          if (forwardToAdmin) {
            await sendNotification(
              requestDoc.userId,
              `${requestDoc.type} Under Review`,
              `Your ${requestDoc.type.toLowerCase()} request of ${requestDoc.amount} was reviewed by Bank Staff and forwarded for final approval.`,
              requestDoc.type === 'Deposit' ? 'deposit' : 'withdrawal'
            );
          }

          return res.status(200).json({
            success: true,
            message: forwardToAdmin
              ? 'Request forwarded to Admin for final approval.'
              : 'Staff note saved.',
          });
        } catch (error) {
          console.error('Error in staff request review:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // PATCH: Approve, Reject, or Forward a Deposit/Withdrawal request (Admin or Staff)
    app.patch(
      '/api/requests/:id/review',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        const session = client.startSession();
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid request ID.' });
          }

          const decision = asString(req.body.decision) as
            | 'Under Review'
            | 'Approved'
            | 'Rejected';
          const reviewNote = asString(req.body.reviewNote);

          if (!['Under Review', 'Approved', 'Rejected'].includes(decision)) {
            return res.status(400).json({
              success: false,
              message: 'Decision must be Under Review, Approved, or Rejected.',
            });
          }

          let targetRequest: DepositWithdrawRequestDocument | null = null;

          await session.withTransaction(async () => {
            const requestDoc = await requestsCollection.findOne(
              { _id: new ObjectId(id) },
              { session }
            );
            if (!requestDoc) throw new Error('HTTP_404:Request not found.');
            if (!['Pending', 'Under Review'].includes(requestDoc.status)) {
              throw new Error(`HTTP_400:Request has already been ${requestDoc.status}.`);
            }
            if (requestDoc.userId === req.user!.id) {
              throw new Error(
                'HTTP_403:You cannot review your own deposit or withdrawal request.'
              );
            }

            if (decision === 'Under Review') {
              await requestsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                  $set: {
                    status: 'Under Review',
                    forwardedByStaffId: req.user!.id,
                    ...(reviewNote ? { staffNote: reviewNote } : {}),
                    updatedAt: new Date(),
                  },
                },
                { session }
              );
              targetRequest = requestDoc;
              return;
            }

            let generatedTxId: string | undefined;

            if (decision === 'Approved') {
              const requestOwner = await usersCollection.findOne(
                buildUserLookupFilter(requestDoc.userId),
                { session, projection: { status: 1 } }
              );
              if (requestOwner?.status && requestOwner.status !== 'active') {
                throw new Error(
                  `HTTP_403:Customer profile is ${requestOwner.status}. Cannot approve financial request.`
                );
              }

              const account = await accountsCollection.findOne(
                { _id: new ObjectId(requestDoc.accountId) },
                { session }
              );
              if (!account || account.status !== 'Active') {
                throw new Error('HTTP_400:Target bank account is missing or not Active.');
              }

              if (
                requestDoc.type === 'Withdrawal' &&
                account.balance - requestDoc.amount < account.minBalance
              ) {
                throw new Error(
                  'HTTP_400:Account no longer has sufficient balance for this withdrawal.'
                );
              }

              const balanceDelta =
                requestDoc.type === 'Deposit' ? requestDoc.amount : -requestDoc.amount;
              await accountsCollection.updateOne(
                { _id: account._id },
                { $inc: { balance: balanceDelta }, $set: { updatedAt: new Date() } },
                { session }
              );

              const settings = await getBankSettings();
              const suspiciousCheck = evaluateSuspiciousActivity(
                requestDoc.amount,
                requestDoc.amount,
                account.dailyTransferLimit,
                settings.largeTransactionAlertThreshold
              );

              generatedTxId = generateReference('TXN');
              await transactionsCollection.insertOne(
                {
                  transactionId: generatedTxId,
                  userId: requestDoc.userId,
                  ...(requestDoc.type === 'Deposit'
                    ? {
                        receiverAccountId: account._id!.toString(),
                        receiverAccountNumber: account.accountNumber,
                      }
                    : {
                        senderAccountId: account._id!.toString(),
                        senderAccountNumber: account.accountNumber,
                      }),
                  type: requestDoc.type,
                  amount: requestDoc.amount,
                  fee: 0,
                  status: 'Completed',
                  description: requestDoc.description,
                  isSuspicious: suspiciousCheck.isSuspicious,
                  ...(suspiciousCheck.reason ? { suspiciousReason: suspiciousCheck.reason } : {}),
                  reviewedBy: req.user!.id,
                  createdAt: new Date(),
                },
                { session }
              );
            }

            await requestsCollection.updateOne(
              { _id: new ObjectId(id) },
              {
                $set: {
                  status: decision,
                  reviewedBy: req.user!.id,
                  reviewNote,
                  ...(generatedTxId ? { transactionId: generatedTxId } : {}),
                  updatedAt: new Date(),
                },
              },
              { session }
            );

            targetRequest = requestDoc;
          });

          if (targetRequest) {
            const reqDoc = targetRequest as DepositWithdrawRequestDocument;
            await sendNotification(
              reqDoc.userId,
              `${reqDoc.type} ${decision}`,
              decision === 'Under Review'
                ? `Your ${reqDoc.type.toLowerCase()} request of ${reqDoc.amount} is now under review.`
                : `Your ${reqDoc.type.toLowerCase()} request of ${reqDoc.amount} for account ${reqDoc.accountNumber} was ${decision.toLowerCase()}.`,
              reqDoc.type === 'Deposit' ? 'deposit' : 'withdrawal'
            );
          }

          return res.status(200).json({
            success: true,
            message: `Request marked as ${decision.toLowerCase()} successfully.`,
          });
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Review failed.';
          if (message.startsWith('HTTP_')) {
            const [codePart, ...rest] = message.split(':');
            return res.status(Number(codePart.replace('HTTP_', '')) || 400).json({
              success: false,
              message: rest.join(':'),
            });
          }
          console.error('Error reviewing request:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        } finally {
          await session.endSession();
        }
      }
    );

    // ========================================================================
    // 9. TRANSACTIONS (History, Search, Date/Type Filter, Pagination & Flagging)
    // ========================================================================

    // GET: Search, filter, and paginate transactions
    app.get('/api/transactions', verifyToken, async (req: Request, res: Response) => {
      try {
        const { role, id: currentUserId } = req.user!;
        const search = asString(req.query.search);
        const type = asString(req.query.type);
        const status = asString(req.query.status);
        const accountId = asString(req.query.accountId);
        const startDate = asString(req.query.startDate);
        const endDate = asString(req.query.endDate);
        const suspiciousOnly = req.query.isSuspicious === 'true';

        const page = Math.max(1, parseInt(asString(req.query.page)) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(asString(req.query.limit)) || 10));
        const skip = (page - 1) * limit;

        const conditions: Record<string, unknown>[] = [];

        if (role === 'customer') {
          conditions.push({ $or: [{ userId: currentUserId }, { receiverUserId: currentUserId }] });
        } else if (asString(req.query.userId)) {
          const targetUserId = asString(req.query.userId);
          conditions.push({ $or: [{ userId: targetUserId }, { receiverUserId: targetUserId }] });
        }

        if (search) {
          const safeRegex = escapeRegex(search);
          conditions.push({
            $or: [
              { transactionId: { $regex: safeRegex, $options: 'i' } },
              { description: { $regex: safeRegex, $options: 'i' } },
              { senderAccountNumber: { $regex: safeRegex, $options: 'i' } },
              { receiverAccountNumber: { $regex: safeRegex, $options: 'i' } },
            ],
          });
        }

        if (type && type !== 'all') conditions.push({ type });
        if (status && status !== 'all') conditions.push({ status });
        if (suspiciousOnly) conditions.push({ isSuspicious: true });

        if (accountId) {
          conditions.push({
            $or: [{ senderAccountId: accountId }, { receiverAccountId: accountId }],
          });
        }

        if (startDate || endDate) {
          const dateFilter: Record<string, Date> = {};
          if (startDate) dateFilter.$gte = new Date(startDate);
          if (endDate) {
            const end = new Date(endDate);
            end.setHours(23, 59, 59, 999);
            dateFilter.$lte = end;
          }
          conditions.push({ createdAt: dateFilter });
        }

        const filter = conditions.length > 0 ? { $and: conditions } : {};

        const [transactions, totalItems] = await Promise.all([
          transactionsCollection
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          transactionsCollection.countDocuments(filter),
        ]);

        const enrichedTransactions = transactions.map((tx) => {
          let direction: 'credit' | 'debit' | 'self' = 'debit';
          if (tx.type === 'Deposit' || tx.type === 'Loan Disbursement') {
            direction = 'credit';
          } else if (tx.type === 'Fund Transfer') {
            if (tx.userId === currentUserId && tx.receiverUserId === currentUserId) {
              direction = 'self';
            } else if (tx.receiverUserId === currentUserId && tx.userId !== currentUserId) {
              direction = 'credit';
            } else {
              direction = 'debit';
            }
          }
          return { ...tx, direction };
        });

        return res.status(200).json({
          success: true,
          data: enrichedTransactions,
          pagination: {
            currentPage: page,
            totalPages: Math.ceil(totalItems / limit) || 1,
            totalItems,
          },
        });
      } catch (error) {
        console.error('Error fetching transactions:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // GET: Single transaction detail (for Transaction Receipt generation)
    app.get('/api/transactions/:id', verifyToken, async (req: Request, res: Response) => {
      try {
        const id = getParam(req.params.id);
        const query = isValidObjectId(id) ? { _id: new ObjectId(id) } : { transactionId: id };

        const tx = await transactionsCollection.findOne(query);
        if (!tx) {
          return res.status(404).json({ success: false, message: 'Transaction not found.' });
        }

        if (
          req.user!.role === 'customer' &&
          tx.userId !== req.user!.id &&
          tx.receiverUserId !== req.user!.id
        ) {
          return res.status(403).json({ success: false, message: 'Access denied.' });
        }

        return res.status(200).json({ success: true, data: tx });
      } catch (error) {
        console.error('Error fetching transaction:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PATCH: Flag or clear a suspicious transaction (Staff or Admin)
    app.patch(
      '/api/transactions/:id/flag',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid transaction ID.' });
          }

          const isSuspicious = Boolean(req.body.isSuspicious);
          const suspiciousReason = asString(req.body.suspiciousReason);

          const result = await transactionsCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                isSuspicious,
                suspiciousReason: isSuspicious
                  ? suspiciousReason || 'Flagged for admin review'
                  : '',
                reviewedBy: req.user!.id,
              },
            }
          );

          if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found.' });
          }

          return res.status(200).json({
            success: true,
            message: isSuspicious ? 'Transaction flagged for review.' : 'Suspicious flag cleared.',
          });
        } catch (error) {
          console.error('Error flagging transaction:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // ========================================================================
    // 10. LOAN MANAGEMENT SYSTEM
    // ========================================================================

    // POST: Customer applies for a loan
    app.post(
      '/api/loans',
      verifyToken,
      requireRole('customer'),
      async (req: Request, res: Response) => {
        try {
          const userId = req.user!.id;
          const accountId = asString(req.body.accountId);
          const loanType = asString(req.body.loanType) as LoanDocument['loanType'];
          const requestedAmount = asPositiveAmount(req.body.requestedAmount);
          const durationMonths = parseInt(
            asString(req.body.durationMonths) || String(req.body.durationMonths)
          );
          const monthlyIncome = asPositiveAmount(req.body.monthlyIncome);
          const employmentStatus = asString(req.body.employmentStatus);
          const description = asString(req.body.description);

          if (
            !isValidObjectId(accountId) ||
            !['Personal', 'Home', 'Auto', 'Business', 'Education'].includes(loanType) ||
            requestedAmount === null ||
            !Number.isInteger(durationMonths) ||
            durationMonths < 3 ||
            durationMonths > 360 ||
            monthlyIncome === null ||
            !employmentStatus
          ) {
            return res.status(400).json({
              success: false,
              message:
                'Please provide valid loan type, amount, duration (3-360 months), income, and employment status.',
            });
          }

          const account = await accountsCollection.findOne({
            _id: new ObjectId(accountId),
            userId,
          });
          if (!account || account.status !== 'Active') {
            return res.status(400).json({
              success: false,
              message: 'An Active bank account owned by you is required for loan disbursement.',
            });
          }

          const rateMap: Record<LoanDocument['loanType'], number> = {
            Home: 7.5,
            Education: 6.5,
            Auto: 8.5,
            Business: 10.0,
            Personal: 11.5,
          };

          const newLoan: LoanDocument = {
            userId,
            accountId,
            loanType,
            requestedAmount,
            interestRate: rateMap[loanType],
            durationMonths,
            monthlyIncome,
            employmentStatus,
            description,
            status: 'Pending',
            remainingBalance: 0,
            monthlyInstallment: 0,
            staffNotes: [],
            repaymentSchedule: [],
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await loansCollection.insertOne(newLoan);

          return res.status(201).json({
            success: true,
            message: 'Loan application submitted successfully.',
            data: { ...newLoan, _id: result.insertedId },
          });
        } catch (error) {
          console.error('Error applying for loan:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // GET: List loans (Customer sees own; Staff/Admin see all)
    app.get('/api/loans', verifyToken, async (req: Request, res: Response) => {
      try {
        const filter: Record<string, unknown> = {};
        if (req.user!.role === 'customer') {
          filter.userId = req.user!.id;
        }
        const status = asString(req.query.status);
        if (status && status !== 'all') filter.status = status;

        const loans = await loansCollection.find(filter).sort({ createdAt: -1 }).toArray();
        return res.status(200).json({ success: true, count: loans.length, data: loans });
      } catch (error) {
        console.error('Error fetching loans:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // GET: Single loan details & repayment schedule
    app.get('/api/loans/:id', verifyToken, async (req: Request, res: Response) => {
      try {
        const id = getParam(req.params.id);
        if (!isValidObjectId(id)) {
          return res.status(400).json({ success: false, message: 'Invalid loan ID.' });
        }

        const loan = await loansCollection.findOne({ _id: new ObjectId(id) });
        if (!loan) {
          return res.status(404).json({ success: false, message: 'Loan not found.' });
        }

        if (req.user!.role === 'customer' && loan.userId !== req.user!.id) {
          return res.status(403).json({ success: false, message: 'Access denied.' });
        }

        return res.status(200).json({ success: true, data: loan });
      } catch (error) {
        console.error('Error fetching loan:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }
    });

    // PATCH: Staff adds internal notes and forwards application for Admin approval
    app.patch(
      '/api/loans/:id/staff-review',
      verifyToken,
      requireRole('staff', 'admin'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid loan ID.' });
          }

          const note = asString(req.body.note);
          const forwardToAdmin = Boolean(req.body.forwardToAdmin);

          const loan = await loansCollection.findOne({ _id: new ObjectId(id) });
          if (!loan) {
            return res.status(404).json({ success: false, message: 'Loan not found.' });
          }
          if (loan.userId === req.user!.id) {
            return res.status(403).json({
              success: false,
              message: 'Cannot review your own loan application.',
            });
          }

          const updateOp: UpdateFilter<LoanDocument> = {
            $set: {
              updatedAt: new Date(),
              ...(forwardToAdmin && loan.status === 'Pending'
                ? { status: 'Under Review' as LoanStatus, forwardedByStaffId: req.user!.id }
                : {}),
            },
          };

          if (note) {
            updateOp.$push = {
              staffNotes: { staffId: req.user!.id, note, createdAt: new Date() },
            };
          }

          await loansCollection.updateOne({ _id: new ObjectId(id) }, updateOp);

          return res.status(200).json({
            success: true,
            message: forwardToAdmin ? 'Loan forwarded for Admin approval.' : 'Internal note added.',
          });
        } catch (error) {
          console.error('Error reviewing loan:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // PATCH: Admin approves (disburses funds atomically) or rejects a loan
    app.patch(
      '/api/loans/:id/decision',
      verifyToken,
      requireRole('admin'),
      async (req: Request, res: Response) => {
        const session = client.startSession();
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid loan ID.' });
          }

          const decision = asString(req.body.decision) as 'Approved' | 'Rejected';
          if (!['Approved', 'Rejected'].includes(decision)) {
            return res
              .status(400)
              .json({ success: false, message: 'Decision must be Approved or Rejected.' });
          }

          let affectedUserId = '';
          let disbursedAmount = 0;

          await session.withTransaction(async () => {
            const loan = await loansCollection.findOne({ _id: new ObjectId(id) }, { session });
            if (!loan) throw new Error('HTTP_404:Loan application not found.');
            if (!['Pending', 'Under Review'].includes(loan.status)) {
              throw new Error(`HTTP_400:Loan is already ${loan.status}.`);
            }
            if (loan.userId === req.user!.id) {
              throw new Error('HTTP_403:Administrators cannot approve their own loans.');
            }

            affectedUserId = loan.userId;

            if (decision === 'Rejected') {
              await loansCollection.updateOne(
                { _id: loan._id },
                {
                  $set: {
                    status: 'Rejected',
                    reviewedByAdminId: req.user!.id,
                    updatedAt: new Date(),
                  },
                },
                { session }
              );
              return;
            }

            const approvedAmount =
              req.body.approvedAmount !== undefined
                ? asPositiveAmount(req.body.approvedAmount)
                : loan.requestedAmount;

            if (approvedAmount === null) {
              throw new Error('HTTP_400:Invalid approvedAmount.');
            }

            const account = await accountsCollection.findOne(
              { _id: new ObjectId(loan.accountId) },
              { session }
            );
            if (!account || account.status !== 'Active') {
              throw new Error(
                'HTTP_400:Customer disbursement account is missing or not Active.'
              );
            }

            const { monthlyInstallment, schedule } = buildRepaymentSchedule(
              approvedAmount,
              loan.interestRate,
              loan.durationMonths
            );
            const totalRepayable = roundCurrency(
              schedule.reduce((sum, item) => sum + item.amount, 0)
            );

            await accountsCollection.updateOne(
              { _id: account._id },
              { $inc: { balance: approvedAmount }, $set: { updatedAt: new Date() } },
              { session }
            );

            await transactionsCollection.insertOne(
              {
                transactionId: generateReference('TXN'),
                userId: loan.userId,
                receiverAccountId: account._id!.toString(),
                receiverAccountNumber: account.accountNumber,
                type: 'Loan Disbursement',
                amount: approvedAmount,
                fee: 0,
                status: 'Completed',
                description: `${loan.loanType} Loan Disbursement`,
                isSuspicious: false,
                reviewedBy: req.user!.id,
                createdAt: new Date(),
              },
              { session }
            );

            await loansCollection.updateOne(
              { _id: loan._id },
              {
                $set: {
                  status: 'Active',
                  approvedAmount,
                  remainingBalance: totalRepayable,
                  monthlyInstallment,
                  repaymentSchedule: schedule,
                  reviewedByAdminId: req.user!.id,
                  updatedAt: new Date(),
                },
              },
              { session }
            );

            disbursedAmount = approvedAmount;
          });

          if (affectedUserId) {
            await sendNotification(
              affectedUserId,
              `Loan ${decision}`,
              decision === 'Approved'
                ? `Your loan has been approved and ${disbursedAmount} has been disbursed to your account.`
                : 'Your loan application was not approved at this time.',
              'loan'
            );
          }

          return res.status(200).json({
            success: true,
            message:
              decision === 'Approved'
                ? 'Loan approved and funds disbursed successfully.'
                : 'Loan application rejected.',
          });
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Loan decision failed.';
          if (message.startsWith('HTTP_')) {
            const [codePart, ...rest] = message.split(':');
            return res.status(Number(codePart.replace('HTTP_', '')) || 400).json({
              success: false,
              message: rest.join(':'),
            });
          }
          console.error('Loan decision error:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        } finally {
          await session.endSession();
        }
      }
    );

    // POST: Customer repays the next installment OR a custom amount atomically (Step 13)
    app.post(
      '/api/loans/:id/repay',
      verifyToken,
      requireRole('customer'),
      async (req: Request, res: Response) => {
        const session = client.startSession();
        try {
          const id = getParam(req.params.id);
          if (!isValidObjectId(id)) {
            return res.status(400).json({ success: false, message: 'Invalid loan ID.' });
          }

          const userId = req.user!.id;
          const customAmount =
            req.body.amount !== undefined && req.body.amount !== ''
              ? asPositiveAmount(req.body.amount)
              : undefined;

          if (req.body.amount !== undefined && req.body.amount !== '' && customAmount === null) {
            return res
              .status(400)
              .json({ success: false, message: 'Repayment amount must be positive.' });
          }

          const transactionPin = asString(req.body.transactionPin);
          const idempotencyKey =
            getParam(req.headers['idempotency-key']) || asString(req.body.idempotencyKey);

          if (idempotencyKey) {
            const duplicateTx = await transactionsCollection.findOne({ idempotencyKey, userId });
            if (duplicateTx) {
              return res.status(200).json({
                success: true,
                message: 'Loan repayment already processed.',
                data: duplicateTx,
              });
            }
          }

          const userDoc = await usersCollection.findOne(buildUserLookupFilter(userId));
          if (userDoc?.transactionPinHash) {
            if (!transactionPin || !verifyPin(transactionPin, userDoc.transactionPinHash)) {
              return res.status(403).json({
                success: false,
                message: 'Valid Transaction PIN is required for loan repayment.',
              });
            }
          } else if (transactionPin) {
            return res.status(400).json({
              success: false,
              message: 'Transaction PIN is not configured on your profile yet.',
            });
          }

          const twoFactorCheck = await verifyTwoFactorIfEnabled(
            userDoc,
            asString(req.body.twoFactorCode),
            buildUserLookupFilter(userId)
          );
          if (!twoFactorCheck.ok) {
            return res.status(twoFactorCheck.status).json({
              success: false,
              message: twoFactorCheck.message,
            });
          }

          let paidAmount = 0;
          let loanCompleted = false;

          await session.withTransaction(async () => {
            const loan = await loansCollection.findOne(
              { _id: new ObjectId(id), userId },
              { session }
            );
            if (!loan) throw new Error('HTTP_404:Loan not found.');
            if (loan.status !== 'Active' || loan.remainingBalance <= 0) {
              throw new Error('HTTP_400:This loan is not active for repayment.');
            }

            const nextInstallment = loan.repaymentSchedule.find(
              (item) => item.status === 'Pending'
            );
            if (!nextInstallment) {
              throw new Error('HTTP_400:No pending installments remaining.');
            }

            const dueForNext = roundCurrency(
              nextInstallment.amount - (nextInstallment.paidAmount || 0)
            );
            const requestedPay = customAmount ?? dueForNext;
            paidAmount = roundCurrency(Math.min(requestedPay, loan.remainingBalance));

            const account = await accountsCollection.findOne(
              { _id: new ObjectId(loan.accountId), userId },
              { session }
            );
            if (!account || account.status !== 'Active') {
              throw new Error('HTTP_400:Linked repayment account is not Active.');
            }
            if (account.balance - paidAmount < account.minBalance) {
              throw new Error('HTTP_400:Insufficient balance in linked account for repayment.');
            }

            await accountsCollection.updateOne(
              { _id: account._id },
              { $inc: { balance: -paidAmount }, $set: { updatedAt: new Date() } },
              { session }
            );

            await transactionsCollection.insertOne(
              {
                transactionId: generateReference('TXN'),
                ...(idempotencyKey ? { idempotencyKey } : {}),
                userId,
                senderAccountId: account._id!.toString(),
                senderAccountNumber: account.accountNumber,
                type: 'Loan Repayment',
                amount: paidAmount,
                fee: 0,
                status: 'Completed',
                description: customAmount
                  ? `Loan Repayment (${loan.loanType} Loan)`
                  : `Loan Installment #${nextInstallment.installmentNumber} (${loan.loanType} Loan)`,
                isSuspicious: false,
                createdAt: new Date(),
              },
              { session }
            );

            // Apply payment across pending installments in order
            let pool = paidAmount;
            const now = new Date();
            const updatedSchedule = loan.repaymentSchedule.map((item) => {
              if (item.status === 'Paid' || pool <= 0) return item;
              const alreadyPaid = item.paidAmount || 0;
              const needed = roundCurrency(item.amount - alreadyPaid);
              if (pool >= needed - 0.001) {
                pool = roundCurrency(Math.max(0, pool - needed));
                return {
                  ...item,
                  paidAmount: item.amount,
                  status: 'Paid' as const,
                  paidAt: now,
                };
              }
              const nextPaid = roundCurrency(alreadyPaid + pool);
              pool = 0;
              return { ...item, paidAmount: nextPaid };
            });

            const newRemaining = Math.max(0, roundCurrency(loan.remainingBalance - paidAmount));
            loanCompleted = newRemaining === 0;

            await loansCollection.updateOne(
              { _id: loan._id },
              {
                $set: {
                  remainingBalance: newRemaining,
                  repaymentSchedule: updatedSchedule,
                  status: loanCompleted ? 'Completed' : 'Active',
                  updatedAt: new Date(),
                },
              },
              { session }
            );
          });

          await sendNotification(
            userId,
            loanCompleted ? 'Loan Fully Repaid' : 'Loan Repayment Received',
            loanCompleted
              ? `Congratulations! Your final repayment of ${paidAmount} completed your loan.`
              : `Your loan repayment of ${paidAmount} has been processed.`,
            'loan'
          );

          return res.status(200).json({
            success: true,
            message: loanCompleted
              ? `Final repayment of ${paidAmount} completed. Loan is now Completed!`
              : `Loan repayment of ${paidAmount} completed successfully.`,
          });
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Repayment failed.';
          if (message.startsWith('HTTP_')) {
            const [codePart, ...rest] = message.split(':');
            return res.status(Number(codePart.replace('HTTP_', '')) || 400).json({
              success: false,
              message: rest.join(':'),
            });
          }
          console.error('Loan repayment error:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        } finally {
          await session.endSession();
        }
      }
    );

    // ========================================================================
    // 11. ADMIN & STAFF CUSTOMER MANAGEMENT + BANK SETTINGS
    // ========================================================================

    // GET: List or search users (Staff sees customers only; Admin sees all roles)
    app.get(
      '/api/admin/users',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const search = asString(req.query.search);
          const verificationStatus = asString(req.query.verificationStatus);
          const conditions: Record<string, unknown>[] = [];

          if (req.user!.role === 'staff') {
            conditions.push({ role: { $in: ['customer', 'user', null] } });
          }

          if (
            verificationStatus &&
            ['incomplete', 'pending', 'verified', 'correction_required'].includes(
              verificationStatus
            )
          ) {
            if (verificationStatus === 'verified') {
              conditions.push({
                $or: [{ verificationStatus: 'verified' }, { kycVerified: true }],
              });
            } else {
              conditions.push({ verificationStatus });
            }
          }

          if (search) {
            const safeRegex = escapeRegex(search);
            conditions.push({
              $or: [
                { name: { $regex: safeRegex, $options: 'i' } },
                { email: { $regex: safeRegex, $options: 'i' } },
                { phone: { $regex: safeRegex, $options: 'i' } },
                { nationalId: { $regex: safeRegex, $options: 'i' } },
              ],
            });
          }

          const filter = conditions.length > 0 ? { $and: conditions } : {};

          const users = await usersCollection
            .find(filter)
            .project({ password: 0, transactionPinHash: 0 })
            .sort({ createdAt: -1 })
            .toArray();

          return res.status(200).json({ success: true, count: users.length, data: users });
        } catch (error) {
          console.error('Error fetching users:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // GET: Single customer details + accounts + recent transactions (Admin or Staff)
    app.get(
      '/api/admin/users/:id',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          const user = await usersCollection.findOne(buildUserLookupFilter(id), {
            projection: { password: 0, transactionPinHash: 0 },
          });

          if (!user) {
            return res.status(404).json({ success: false, message: 'Customer not found.' });
          }

          if (req.user!.role === 'staff' && normalizeRole(user.role) !== 'customer') {
            return res
              .status(403)
              .json({ success: false, message: 'Staff can only view customer profiles.' });
          }

          const targetUserId = user._id?.toString() || id;
          const [accounts, recentTransactions, customerProfile] = await Promise.all([
            accountsCollection.find({ userId: targetUserId }).toArray(),
            transactionsCollection
              .find({ $or: [{ userId: targetUserId }, { receiverUserId: targetUserId }] })
              .sort({ createdAt: -1 })
              .limit(20)
              .toArray(),
            customerProfilesCollection.findOne({ userId: targetUserId }),
          ]);

          return res.status(200).json({
            success: true,
            data: { user, customerProfile: customerProfile || null, accounts, recentTransactions },
          });
        } catch (error) {
          console.error('Error fetching customer details:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // POST: Staff or Admin registers a new walk-in customer with Better-Auth login credentials
    app.post(
      '/api/staff/customers',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const name = asString(req.body.name);
          const email = asString(req.body.email).toLowerCase();
          const rawPassword = asString(req.body.password);
          const phone = asString(req.body.phone);
          const address = asString(req.body.address);
          const nationalId = asString(req.body.nationalId);

          if (!name || !email) {
            return res
              .status(400)
              .json({ success: false, message: 'Customer name and email are required.' });
          }

          if (rawPassword && rawPassword.length < 8) {
            return res.status(400).json({
              success: false,
              message: 'Temporary login password must be at least 8 characters.',
            });
          }

          const initialPassword =
            rawPassword || `Finova@${crypto.randomBytes(4).toString('hex')}`;

          const existing = await usersCollection.findOne({ email });
          if (existing) {
            return res
              .status(409)
              .json({ success: false, message: 'A customer with this email already exists.' });
          }

          const now = new Date();
          let canonicalCustomerId = '';

          // Primary path: ask Better-Auth on Next.js to create both `user` and credential `account`
          try {
            const signUpRes = await fetch(`${clientUrl}/api/auth/sign-up/email`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Origin: clientUrl,
                Referer: clientUrl,
              },
              body: JSON.stringify({ name, email, password: initialPassword }),
            });

            if (signUpRes.ok) {
              const signUpJson = (await signUpRes.json()) as {
                user?: { id?: string };
              };
              if (signUpJson?.user?.id) {
                canonicalCustomerId = signUpJson.user.id;
                await usersCollection.updateOne(buildUserLookupFilter(canonicalCustomerId), {
                  $set: {
                    name,
                    email,
                    phone,
                    address,
                    nationalId,
                    role: 'customer',
                    status: 'active',
                    kycVerified: true,
                    verificationStatus: 'verified',
                    verifiedByStaffId: req.user!.id,
                    verifiedAt: now,
                    updatedAt: now,
                  },
                });
              }
            } else {
              const errBody = (await signUpRes.json().catch(() => null)) as {
                message?: string;
              } | null;
              return res.status(signUpRes.status).json({
                success: false,
                message: errBody?.message || 'Could not create customer login credentials.',
              });
            }
          } catch {
            // Fallback when Better-Auth endpoint is unreachable: write compatible user + account docs directly
            const newCustomer: UserDocument = {
              name,
              email,
              phone,
              address,
              nationalId,
              role: 'customer',
              status: 'active',
              kycVerified: true,
              verificationStatus: 'verified',
              verifiedByStaffId: req.user!.id,
              verifiedAt: now,
              createdAt: now,
              updatedAt: now,
            };

            const userInsert = await usersCollection.insertOne(newCustomer);
            canonicalCustomerId = userInsert.insertedId.toString();

            await db.collection('account').insertOne({
              userId: userInsert.insertedId,
              accountId: canonicalCustomerId,
              providerId: 'credential',
              password: hashBetterAuthPassword(initialPassword),
              createdAt: now,
              updatedAt: now,
            });
          }

          if (canonicalCustomerId) {
            await customerProfilesCollection.updateOne(
              { userId: canonicalCustomerId },
              {
                $set: {
                  userId: canonicalCustomerId,
                  fullName: name,
                  email,
                  phone,
                  address,
                  nationalId,
                  verificationStatus: 'verified',
                  verificationNote: '',
                  verifiedByStaffId: req.user!.id,
                  verifiedAt: now,
                  updatedAt: now,
                },
                $setOnInsert: {
                  dateOfBirth: '',
                  gender: '',
                  city: '',
                  occupation: '',
                  nidDocumentUrl: '',
                  createdAt: now,
                },
              },
              { upsert: true }
            );
          }

          const createdCustomer = canonicalCustomerId
            ? await usersCollection.findOne(buildUserLookupFilter(canonicalCustomerId), {
                projection: { password: 0, transactionPinHash: 0 },
              })
            : null;

          return res.status(201).json({
            success: true,
            message: 'Customer registered with login credentials and marked KYC verified.',
            data: createdCustomer,
            temporaryPassword: rawPassword ? undefined : initialPassword,
          });
        } catch (error) {
          console.error('Error registering customer:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // PATCH: Staff verifies KYC or requests correction; Admin can also change status or role
    app.patch(
      '/api/admin/users/:id/status',
      verifyToken,
      requireRole('admin', 'staff'),
      async (req: Request, res: Response) => {
        try {
          const id = getParam(req.params.id);
          const filter = buildUserLookupFilter(id);
          const targetUser = await usersCollection.findOne(filter);

          if (!targetUser) {
            return res.status(404).json({ success: false, message: 'User not found.' });
          }

          const updates: Partial<UserDocument> = { updatedAt: new Date() };
          const verificationStatus = asString(req.body.verificationStatus) as VerificationStatus;
          const verificationNote = asString(req.body.verificationNote);

          if (verificationStatus) {
            if (!['incomplete', 'pending', 'verified', 'correction_required'].includes(verificationStatus)) {
              return res
                .status(400)
                .json({ success: false, message: 'Invalid verification status.' });
            }
            updates.verificationStatus = verificationStatus;
            updates.kycVerified = verificationStatus === 'verified';
            updates.verificationNote = verificationNote;
            if (verificationStatus === 'verified') {
              updates.verifiedByStaffId = req.user!.id;
              updates.verifiedAt = new Date();
            }
          } else if (typeof req.body.kycVerified === 'boolean') {
            updates.kycVerified = req.body.kycVerified;
            updates.verificationStatus = req.body.kycVerified ? 'verified' : 'incomplete';
            if (verificationNote) updates.verificationNote = verificationNote;
            if (req.body.kycVerified) {
              updates.verifiedByStaffId = req.user!.id;
              updates.verifiedAt = new Date();
            }
          }

          if (req.user!.role === 'admin') {
            const status = asString(req.body.status) as UserAccountStatus;
            if (status) {
              if (!['active', 'deactivated', 'blocked'].includes(status)) {
                return res.status(400).json({ success: false, message: 'Invalid account status.' });
              }
              updates.status = status;
            }

            const role = asString(req.body.role) as UserRole;
            if (role) {
              if (!['admin', 'staff', 'customer'].includes(role)) {
                return res.status(400).json({ success: false, message: 'Invalid role.' });
              }
              updates.role = role;
            }
          } else if (req.body.status !== undefined || req.body.role !== undefined) {
            return res.status(403).json({
              success: false,
              message: 'Only Administrators can change account status or user roles.',
            });
          }

          await usersCollection.updateOne(filter, { $set: updates });

          const targetCanonicalId = targetUser._id?.toString() || id;

          // Keep customerProfiles collection synchronized with KYC review decision
          if (updates.verificationStatus !== undefined) {
            const profileSync: Partial<CustomerProfileDocument> = {
              verificationStatus: updates.verificationStatus,
              verificationNote: updates.verificationNote ?? '',
              updatedAt: new Date(),
              ...(updates.verifiedByStaffId ? { verifiedByStaffId: updates.verifiedByStaffId } : {}),
              ...(updates.verifiedAt ? { verifiedAt: updates.verifiedAt } : {}),
            };
            await customerProfilesCollection.updateOne(
              { userId: targetCanonicalId },
              {
                $set: profileSync,
                $setOnInsert: {
                  userId: targetCanonicalId,
                  fullName: targetUser.name || '',
                  email: targetUser.email || '',
                  phone: targetUser.phone || '',
                  dateOfBirth: targetUser.dateOfBirth || '',
                  gender: targetUser.gender || '',
                  address: targetUser.address || '',
                  city: targetUser.city || '',
                  nationalId: targetUser.nationalId || '',
                  occupation: targetUser.occupation || '',
                  nidDocumentUrl: targetUser.nidDocumentUrl || '',
                  createdAt: new Date(),
                },
              },
              { upsert: true }
            );
          }

          if (updates.verificationStatus === 'verified') {
            await sendNotification(
              targetCanonicalId,
              'KYC Profile Verified',
              'Your identity profile has been verified. You may now open and use bank accounts.',
              'kyc'
            );
          } else if (updates.verificationStatus === 'correction_required') {
            await sendNotification(
              targetCanonicalId,
              'Profile Correction Requested',
              verificationNote ||
                'Staff requested updates to your KYC profile. Please review and resubmit.',
              'kyc'
            );
          }

          return res.status(200).json({ success: true, message: 'User status updated successfully.' });
        } catch (error) {
          console.error('Error updating user status:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // GET & PUT: Bank-wide financial limits & alert thresholds (Admin only)
    app.get(
      '/api/admin/settings',
      verifyToken,
      requireRole('admin'),
      async (_req: Request, res: Response) => {
        const settings = await getBankSettings();
        return res.status(200).json({ success: true, data: settings });
      }
    );

    app.put(
      '/api/admin/settings',
      verifyToken,
      requireRole('admin'),
      async (req: Request, res: Response) => {
        try {
          const updates: Partial<BankSettingsDocument> = { updatedAt: new Date() };

          if (req.body.defaultDailyTransferLimit !== undefined) {
            const val = asPositiveAmount(req.body.defaultDailyTransferLimit);
            if (val === null)
              return res.status(400).json({ success: false, message: 'Invalid daily limit.' });
            updates.defaultDailyTransferLimit = val;
          }
          if (req.body.defaultMaxSingleTransaction !== undefined) {
            const val = asPositiveAmount(req.body.defaultMaxSingleTransaction);
            if (val === null)
              return res
                .status(400)
                .json({ success: false, message: 'Invalid max single limit.' });
            updates.defaultMaxSingleTransaction = val;
          }
          if (req.body.largeTransactionAlertThreshold !== undefined) {
            const val = asPositiveAmount(req.body.largeTransactionAlertThreshold);
            if (val === null)
              return res.status(400).json({ success: false, message: 'Invalid alert threshold.' });
            updates.largeTransactionAlertThreshold = val;
          }
          if (req.body.defaultMinBalance !== undefined) {
            const num = Number(req.body.defaultMinBalance);
            if (!Number.isFinite(num) || num < 0) {
              return res
                .status(400)
                .json({ success: false, message: 'Invalid minimum balance.' });
            }
            updates.defaultMinBalance = roundCurrency(num);
          }
          if (req.body.transferFeePercent !== undefined) {
            const num = Number(req.body.transferFeePercent);
            if (!Number.isFinite(num) || num < 0 || num > 10) {
              return res.status(400).json({
                success: false,
                message: 'Transfer fee must be between 0% and 10%.',
              });
            }
            updates.transferFeePercent = roundCurrency(num);
          }

          await settingsCollection.updateOne(
            { _id: 'global_limits' },
            { $set: updates },
            { upsert: true }
          );

          let updatedAccountsCount = 0;
          if (req.body.applyToExistingAccounts === true) {
            const accountLimitUpdates: Partial<BankAccountDocument> = { updatedAt: new Date() };
            if (updates.defaultDailyTransferLimit !== undefined) {
              accountLimitUpdates.dailyTransferLimit = updates.defaultDailyTransferLimit;
            }
            if (updates.defaultMaxSingleTransaction !== undefined) {
              accountLimitUpdates.maxSingleTransaction = updates.defaultMaxSingleTransaction;
            }
            if (updates.defaultMinBalance !== undefined) {
              accountLimitUpdates.minBalance = updates.defaultMinBalance;
            }
            const bulkRes = await accountsCollection.updateMany({}, { $set: accountLimitUpdates });
            updatedAccountsCount = bulkRes.modifiedCount;
          }

          return res.status(200).json({
            success: true,
            message:
              req.body.applyToExistingAccounts === true
                ? `Bank settings updated and applied to ${updatedAccountsCount} existing account(s).`
                : 'Bank settings updated successfully.',
          });
        } catch (error) {
          console.error('Error updating bank settings:', error);
          return res.status(500).json({ success: false, message: 'Internal server error.' });
        }
      }
    );

    // ========================================================================
    // 12. DASHBOARD ANALYTICS & CHARTS (Customer, Staff & Admin)
    // ========================================================================

    // GET: Personalized Customer Dashboard metrics & chart datasets
    app.get('/api/dashboard/customer', verifyToken, async (req: Request, res: Response) => {
      try {
        const userId = req.user!.id;

        const [
          userDoc,
          accounts,
          txTotals,
          activeLoansCount,
          recentTransactions,
          monthlyCashflow,
          txDistribution,
        ] = await Promise.all([
          usersCollection.findOne(buildUserLookupFilter(userId), {
            projection: { password: 0, transactionPinHash: 0 },
          }),
          accountsCollection.find({ userId }).toArray(),
          transactionsCollection
            .aggregate([
              { $match: { status: 'Completed', $or: [{ userId }, { receiverUserId: userId }] } },
              { $group: { _id: '$type', total: { $sum: '$amount' } } },
            ])
            .toArray(),
          loansCollection.countDocuments({ userId, status: 'Active' }),
          transactionsCollection
            .find({ $or: [{ userId }, { receiverUserId: userId }] })
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray(),
          transactionsCollection
            .aggregate([
              { $match: { status: 'Completed', $or: [{ userId }, { receiverUserId: userId }] } },
              {
                $group: {
                  _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
                  deposits: {
                    $sum: {
                      $cond: [
                        {
                          $or: [
                            { $eq: ['$type', 'Deposit'] },
                            { $eq: ['$type', 'Loan Disbursement'] },
                            {
                              $and: [
                                { $eq: ['$type', 'Fund Transfer'] },
                                { $eq: ['$receiverUserId', userId] },
                                { $ne: ['$userId', userId] },
                              ],
                            },
                          ],
                        },
                        '$amount',
                        0,
                      ],
                    },
                  },
                  spending: {
                    $sum: {
                      $cond: [
                        {
                          $or: [
                            { $eq: ['$type', 'Withdrawal'] },
                            { $eq: ['$type', 'Loan Repayment'] },
                            {
                              $and: [
                                { $eq: ['$type', 'Fund Transfer'] },
                                { $eq: ['$userId', userId] },
                                { $ne: ['$receiverUserId', userId] },
                              ],
                            },
                          ],
                        },
                        '$amount',
                        0,
                      ],
                    },
                  },
                },
              },
              { $sort: { '_id.year': -1, '_id.month': -1 } },
              { $limit: 6 },
              { $sort: { '_id.year': 1, '_id.month': 1 } },
            ])
            .toArray(),
          transactionsCollection
            .aggregate([
              { $match: { status: 'Completed', $or: [{ userId }, { receiverUserId: userId }] } },
              { $group: { _id: '$type', count: { $sum: 1 }, amount: { $sum: '$amount' } } },
              { $project: { _id: 0, name: '$_id', count: 1, value: '$amount' } },
            ])
            .toArray(),
        ]);

        const totalBalance = roundCurrency(accounts.reduce((sum, acc) => sum + acc.balance, 0));
        const totalDeposits = roundCurrency(
          txTotals.find((t) => t._id === 'Deposit')?.total || 0
        );
        const totalWithdrawals = roundCurrency(
          txTotals.find((t) => t._id === 'Withdrawal')?.total || 0
        );
        const monthNames = [
          'Jan',
          'Feb',
          'Mar',
          'Apr',
          'May',
          'Jun',
          'Jul',
          'Aug',
          'Sep',
          'Oct',
          'Nov',
          'Dec',
        ];

        return res.status(200).json({
          success: true,
          data: {
            profile: {
              kycVerified: Boolean(
                userDoc?.kycVerified || userDoc?.verificationStatus === 'verified'
              ),
              verificationStatus: userDoc?.verificationStatus
                ? userDoc.verificationStatus
                : userDoc?.kycVerified
                ? 'verified'
                : 'incomplete',
              verificationNote: userDoc?.verificationNote || '',
            },
            cards: {
              totalBalance,
              totalDeposits,
              totalWithdrawals,
              activeLoansCount,
              totalAccounts: accounts.length,
            },
            accounts,
            charts: {
              monthlyCashflow: monthlyCashflow.map((m) => ({
                month: `${monthNames[m._id.month - 1]} ${m._id.year}`,
                deposits: roundCurrency(m.deposits),
                spending: roundCurrency(m.spending),
              })),
              transactionDistribution: txDistribution,
            },
            recentTransactions,
          },
        });
      } catch (error) {
        console.error('Customer dashboard error:', error);
        return res
          .status(500)
          .json({ success: false, message: 'Failed to load customer dashboard.' });
      }
    });

    // GET: Staff Operations Queue & Daily Overview
    app.get(
      '/api/dashboard/staff',
      verifyToken,
      requireRole('staff', 'admin'),
      async (_req: Request, res: Response) => {
        try {
          const startOfDay = new Date();
          startOfDay.setHours(0, 0, 0, 0);

          const [
            pendingVerifications,
            pendingRequests,
            pendingAccountRequests,
            pendingLoans,
            transactionsToday,
            flaggedTransactions,
          ] = await Promise.all([
            usersCollection.countDocuments({
              role: { $nin: ['admin', 'staff'] },
              kycVerified: { $ne: true },
            }),
            requestsCollection.countDocuments({ status: { $in: ['Pending', 'Under Review'] } }),
            accountRequestsCollection.countDocuments({ status: 'Pending' }),
            loansCollection.countDocuments({ status: { $in: ['Pending', 'Under Review'] } }),
            transactionsCollection.countDocuments({ createdAt: { $gte: startOfDay } }),
            transactionsCollection.countDocuments({ isSuspicious: true }),
          ]);

          return res.status(200).json({
            success: true,
            data: {
              pendingVerifications,
              pendingRequests,
              pendingAccountRequests,
              pendingLoans,
              transactionsToday,
              flaggedTransactions,
            },
          });
        } catch (error) {
          console.error('Staff dashboard error:', error);
          return res
            .status(500)
            .json({ success: false, message: 'Failed to load staff overview.' });
        }
      }
    );

    // GET: Admin & Staff Banking Overview Analytics
    app.get(
      '/api/dashboard/admin',
      verifyToken,
      requireRole('admin', 'staff'),
      async (_req: Request, res: Response) => {
        try {
          const [
            totalCustomers,
            totalAccounts,
            totalTransactions,
            pendingLoans,
            pendingRequests,
            pendingVerifications,
            flaggedTransactions,
            balanceAgg,
            txVolumeByType,
            accountDistribution,
            loanStats,
            monthlyActivity,
          ] = await Promise.all([
            usersCollection.countDocuments({ role: { $nin: ['admin', 'staff'] } }),
            accountsCollection.countDocuments(),
            transactionsCollection.countDocuments(),
            loansCollection.countDocuments({ status: { $in: ['Pending', 'Under Review'] } }),
            requestsCollection.countDocuments({ status: { $in: ['Pending', 'Under Review'] } }),
            usersCollection.countDocuments({
              role: { $nin: ['admin', 'staff'] },
              kycVerified: { $ne: true },
            }),
            transactionsCollection.countDocuments({ isSuspicious: true }),
            accountsCollection
              .aggregate([{ $group: { _id: null, totalBalance: { $sum: '$balance' } } }])
              .toArray(),
            transactionsCollection
              .aggregate([
                { $match: { status: 'Completed' } },
                { $group: { _id: '$type', total: { $sum: '$amount' } } },
              ])
              .toArray(),
            accountsCollection
              .aggregate([
                { $group: { _id: '$accountType', count: { $sum: 1 }, balance: { $sum: '$balance' } } },
                { $project: { _id: 0, name: '$_id', count: 1, balance: 1 } },
              ])
              .toArray(),
            loansCollection
              .aggregate([
                { $group: { _id: '$status', count: { $sum: 1 } } },
                { $project: { _id: 0, status: '$_id', count: 1 } },
              ])
              .toArray(),
            transactionsCollection
              .aggregate([
                { $match: { status: 'Completed' } },
                {
                  $group: {
                    _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
                    volume: { $sum: '$amount' },
                    deposits: { $sum: { $cond: [{ $eq: ['$type', 'Deposit'] }, '$amount', 0] } },
                    withdrawals: {
                      $sum: { $cond: [{ $eq: ['$type', 'Withdrawal'] }, '$amount', 0] },
                    },
                    count: { $sum: 1 },
                  },
                },
                { $sort: { '_id.year': -1, '_id.month': -1 } },
                { $limit: 6 },
                { $sort: { '_id.year': 1, '_id.month': 1 } },
              ])
              .toArray(),
          ]);

          const totalBankBalance = roundCurrency(balanceAgg[0]?.totalBalance || 0);
          const totalDeposits = roundCurrency(
            txVolumeByType.find((t) => t._id === 'Deposit')?.total || 0
          );
          const totalWithdrawals = roundCurrency(
            txVolumeByType.find((t) => t._id === 'Withdrawal')?.total || 0
          );
          const monthNames = [
            'Jan',
            'Feb',
            'Mar',
            'Apr',
            'May',
            'Jun',
            'Jul',
            'Aug',
            'Sep',
            'Oct',
            'Nov',
            'Dec',
          ];

          return res.status(200).json({
            success: true,
            data: {
              cards: {
                totalCustomers,
                totalAccounts,
                totalBankBalance,
                totalDeposits,
                totalWithdrawals,
                totalTransactions,
                pendingLoans,
                pendingRequests,
                pendingVerifications,
                flaggedTransactions,
              },
              charts: {
                monthlyActivity: monthlyActivity.map((m) => ({
                  month: `${monthNames[m._id.month - 1]} ${m._id.year}`,
                  volume: roundCurrency(m.volume),
                  deposits: roundCurrency(m.deposits),
                  withdrawals: roundCurrency(m.withdrawals),
                  count: m.count,
                })),
                accountDistribution,
                loanStatistics: loanStats,
              },
            },
          });
        } catch (error) {
          console.error('Admin dashboard error:', error);
          return res
            .status(500)
            .json({ success: false, message: 'Failed to load admin analytics.' });
        }
      }
    );

    // ========================================================================
    // 13. HEALTH CHECK & SERVER START
    // ========================================================================

    app.get('/', (_req: Request, res: Response) => {
      res.status(200).json({
        success: true,
        message: 'Finova Digital Banking API is active.',
        database: dbName,
      });
    });

    app.listen(port, () => {
      console.log(`Finova Digital Banking API running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error('Critical database startup error:', error);
    process.exit(1);
  }
}

run().catch(console.dir);
