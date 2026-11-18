<?php

namespace App\Controller;

use App\Entity\User;
use App\Exception\InvalidRefreshTokenException;
use App\Repository\DeviceRepository;
use App\Repository\UserRepository;
use App\Service\RefreshTokenService;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api')]
class AuthController extends AbstractController
{
    public function __construct(
        private readonly RefreshTokenService $refreshTokens,
        private readonly JWTTokenManagerInterface $jwt,
    ) {
    }

    #[Route('/login', name: 'api_login', methods: ['POST'])]
    public function login(
        Request $request,
        UserRepository $users,
        UserPasswordHasherInterface $hasher,
    ): JsonResponse {
        $data = $this->json_body($request);
        $email = (string) ($data['email'] ?? '');
        $password = (string) ($data['password'] ?? '');

        $user = $email !== '' ? $users->findOneBy(['email' => $email]) : null;
        if (!$user instanceof User || !$hasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        [$device, $refresh] = $this->refreshTokens->createDevice($user, $request);

        return new JsonResponse([
            'access_token' => $this->jwt->create($user),
            'refresh_token' => $refresh,
            'device_id' => $device->getId(),
        ]);
    }

    #[Route('/token/refresh', name: 'api_token_refresh', methods: ['POST'])]
    public function refresh(Request $request): JsonResponse
    {
        $token = (string) ($this->json_body($request)['refresh_token'] ?? '');

        try {
            [$device, $refresh] = $this->refreshTokens->rotate($token, $request);
        } catch (InvalidRefreshTokenException $e) {
            return new JsonResponse(['error' => $e->getMessage()], 401);
        }

        return new JsonResponse([
            'access_token' => $this->jwt->create($device->getUser()),
            'refresh_token' => $refresh,
            'device_id' => $device->getId(),
        ]);
    }

    #[Route('/logout', name: 'api_logout', methods: ['POST'])]
    public function logout(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $token = (string) ($this->json_body($request)['refresh_token'] ?? '');

        try {
            $this->refreshTokens->revoke($token, $user);
        } catch (InvalidRefreshTokenException $e) {
            return new JsonResponse(['error' => $e->getMessage()], 401);
        }

        return new JsonResponse(['status' => 'ok']);
    }

    #[Route('/devices', name: 'api_devices', methods: ['GET'])]
    public function devices(DeviceRepository $devices): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $fmt = static fn (?\DateTimeImmutable $d) => $d?->format(DATE_ATOM);

        return new JsonResponse(array_map(static fn ($d) => [
            'id' => $d->getId(),
            'ip' => $d->getIp(),
            'user_agent' => $d->getUserAgent(),
            'last_used_at' => $fmt($d->getLastUsedAt()),
            'created_at' => $fmt($d->getCreatedAt()),
            'expires_at' => $fmt($d->getExpiresAt()),
            'is_revoked' => $d->isRevoked(),
            'is_compromised' => $d->isCompromised(),
        ], $devices->findByUserNewestFirst($user)));
    }

    #[Route('/password/change', name: 'api_password_change', methods: ['POST'])]
    public function changePassword(
        Request $request,
        UserPasswordHasherInterface $hasher,
        EntityManagerInterface $em,
    ): JsonResponse {
        /** @var User $user */
        $user = $this->getUser();
        $data = $this->json_body($request);
        $new = (string) ($data['new_password'] ?? '');

        if (!$hasher->isPasswordValid($user, (string) ($data['current_password'] ?? ''))) {
            return new JsonResponse(['error' => 'Invalid current password'], 400);
        }
        if (mb_strlen($new) < 8) {
            return new JsonResponse(['error' => 'New password must be at least 8 characters'], 400);
        }

        $user->setPassword($hasher->hashPassword($user, $new));
        $this->refreshTokens->revokeAllForUser($user, false);
        $em->flush();

        return new JsonResponse(['status' => 'ok']);
    }

    private function json_body(Request $request): array
    {
        $data = json_decode($request->getContent(), true);
        return is_array($data) ? $data : [];
    }
}
