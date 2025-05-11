import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { verifyJwtToken } from "@/lib/auth"

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Rotas públicas que não precisam de autenticação
  const publicRoutes = ["/", "/login", "/register", "/hotels", "/access-denied", "/offline"]
  const isPublicRoute = publicRoutes.some((route) => pathname === route || pathname.startsWith("/hotels/"))

  // Rotas administrativas que precisam de permissão de admin
  const isAdminRoute = pathname.startsWith("/admin")

  // Rotas de assets estáticos que devem ter cache
  const isStaticAsset = pathname.match(/\.(jpg|jpeg|png|gif|svg|webp|avif|css|js|woff2)$/)

  // Adicionar cabeçalhos de cache para assets estáticos
  if (isStaticAsset) {
    const response = NextResponse.next()

    // Cache por 1 ano para assets estáticos
    response.headers.set("Cache-Control", "public, max-age=31536000, immutable")
    return response
  }

  // Verificar o token JWT nos cookies
  const token = request.cookies.get("token")?.value

  if (!token) {
    // Se não há token e a rota não é pública, redirecionar para login
    if (!isPublicRoute) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
    return NextResponse.next()
  }

  try {
    // Verificar e decodificar o token
    const decodedToken = await verifyJwtToken(token)
    const userRole = decodedToken.role

    // Verificar permissões para rotas administrativas
    if (isAdminRoute && !["SUPER_ADMIN", "ADMIN"].includes(userRole)) {
      return NextResponse.redirect(new URL("/access-denied", request.url))
    }

    // Adicionar informações do usuário ao cabeçalho para uso posterior
    const requestHeaders = new Headers(request.headers)
    requestHeaders.set("x-user-id", decodedToken.id)
    requestHeaders.set("x-user-role", userRole)

    // Adicionar cabeçalhos de segurança
    const response = NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    })

    // Adicionar cabeçalhos de segurança
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    // Adicionar cabeçalhos de cache para páginas dinâmicas
    if (!isStaticAsset && !isAdminRoute) {
      response.headers.set("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
    }

    return response
  } catch (error) {
    // Token inválido ou expirado
    if (!isPublicRoute) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
    return NextResponse.next()
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public (public files)
     * - api routes that don't require authentication
     */
    "/((?!_next/static|_next/image|favicon.ico|public|api/public).*)",
  ],
}
