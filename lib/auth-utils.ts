import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { Role } from "@prisma/client";

export async function getSession() {
  return await getServerSession(authOptions);
}

export async function requireAuth(requiredRoles?: Role[]) {
  const session = await getSession();

  if (!session || !session.user) {
    throw new Error("Unauthorized");
  }

  if (requiredRoles && !requiredRoles.includes((session.user as any).role)) {
    throw new Error("Forbidden");
  }

  return session;
}

export async function getCurrentUser() {
  const session = await getSession();

  if (!session?.user?.email) {
    return null;
  }

  // Fetch full user from database
  const { prisma } = await import("@/lib/prisma");
  const user = await prisma.user.findUnique({
    where: { email: session.user.email },
    include: {
      student: true,
      teacher: true,
      admin: true,
    },
  });

  return user;
}
