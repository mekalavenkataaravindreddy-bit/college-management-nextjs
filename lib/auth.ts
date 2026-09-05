import { type NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    // Credentials Provider for email/password login
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Invalid credentials");
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
          include: {
            student: true,
            teacher: true,
            admin: true,
          },
        });

        if (!user) {
          throw new Error("User not found");
        }

        if (!user.isActive) {
          throw new Error("User account is inactive");
        }

        const isPasswordValid = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!isPasswordValid) {
          throw new Error("Invalid password");
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          image: null,
        };
      },
    }),

    // GitHub OAuth Provider
    GitHubProvider({
      clientId: process.env.GITHUB_ID || "",
      clientSecret: process.env.GITHUB_SECRET || "",
      allowDangerousEmailAccountLinking: true,
    }),

    // Google OAuth Provider
    GoogleProvider({
      clientId: process.env.GOOGLE_ID || "",
      clientSecret: process.env.GOOGLE_SECRET || "",
      allowDangerousEmailAccountLinking: true,
    }),
  ],

  callbacks: {
    // JWT callback - add user info to token
    async jwt({ token, user, account }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.role = (user as any).role || "STUDENT";
      }

      if (account) {
        token.provider = account.provider;
      }

      return token;
    },

    // Session callback - add user info to session
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.email = token.email as string;
        session.user.name = token.name as string;
        (session.user as any).role = token.role;
      }

      return session;
    },

    // Sign in callback - validate user
    async signIn({ user, account, profile }) {
      // Allow OAuth sign in
      if (account?.provider !== "credentials") {
        // Check if user exists, if not create with STUDENT role
        const existingUser = await prisma.user.findUnique({
          where: { email: user.email || "" },
        });

        if (!existingUser && user.email) {
          await prisma.user.create({
            data: {
              email: user.email,
              name: user.name || "User",
              password: await bcrypt.hash(Math.random().toString(), 10),
              role: "STUDENT",
              isActive: true,
            },
          });
        }

        return true;
      }

      return true;
    },

    // Redirect callback
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url;
      return baseUrl;
    },
  },

  pages: {
    signIn: "/auth/signin",
    error: "/auth/error",
    newUser: "/auth/register",
  },

  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // 24 hours
  },

  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },

  events: {
    async signIn({ user, account, profile, isNewUser }) {
      console.log(`User ${user.email} signed in with ${account?.provider}`);
    },
    async signOut({ token }) {
      console.log(`User signed out`);
    },
  },

  debug: process.env.NODE_ENV === "development",
};
