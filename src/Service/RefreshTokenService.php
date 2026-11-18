<?php

namespace App\Service;

use App\Entity\Device;
use App\Entity\User;
use App\Exception\InvalidRefreshTokenException;
use App\Repository\DeviceRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class RefreshTokenService
{
    public const TTL = '+7 days';
    public const MAX_DEVICES = 5;

    public function __construct(
        private readonly EntityManagerInterface $em,
        private readonly DeviceRepository $devices,
    ) {
    }

    public function createDevice(User $user, Request $request): array
    {
        $this->enforceDeviceLimit($user);

        $device = new Device($user);
        $device->setIp($request->getClientIp())
            ->setUserAgent($request->headers->get('User-Agent'));
        $plain = $this->issueNewToken($device);

        $this->em->persist($device);
        $this->em->flush();

        return [$device, $plain];
    }

    public function rotate(string $token, Request $request): array
    {
        [$device, $secret] = $this->findDeviceByToken($token);

        if ($device->isCompromised() || $device->isRevoked()) {
            throw new InvalidRefreshTokenException('Token revoked');
        }

        $matchesCurrent = $this->matches($secret, $device->getRefreshToken());
        $matchesPrevious = $this->matches($secret, $device->getPreviousRefreshToken());

        if (!$matchesCurrent) {
            if ($matchesPrevious) {
                $this->markCompromised($device);
            }
            throw new InvalidRefreshTokenException('Invalid refresh token');
        }

        if ($device->isExpired()) {
            throw new InvalidRefreshTokenException('Refresh token expired');
        }

        $device->setPreviousRefreshToken($device->getRefreshToken());
        $plain = $this->issueNewToken($device);
        $device->setIp($request->getClientIp())
            ->setUserAgent($request->headers->get('User-Agent'));
        $this->em->flush();

        return [$device, $plain];
    }

    public function revoke(string $token, User $user): void
    {
        [$device, $secret] = $this->findDeviceByToken($token);

        if ($device->getUser()->getId() !== $user->getId()) {
            throw new InvalidRefreshTokenException('Invalid refresh token');
        }
        if (!$this->matches($secret, $device->getRefreshToken())) {
            throw new InvalidRefreshTokenException('Invalid refresh token');
        }

        $device->setRefreshToken(null)->setPreviousRefreshToken(null)->setIsRevoked(true);
        $this->em->flush();
    }

    public function revokeAllForUser(User $user, bool $flush = true): void
    {
        foreach ($this->devices->findBy(['user' => $user]) as $device) {
            $device->setRefreshToken(null)->setPreviousRefreshToken(null)->setIsRevoked(true);
        }
        if ($flush) {
            $this->em->flush();
        }
    }

    private function matches(string $secret, ?string $hash): bool
    {
        return $hash !== null && $hash !== '' && password_verify($secret, $hash);
    }

    private function markCompromised(Device $device): void
    {
        $this->revokeAllForUser($device->getUser(), false);
        $device->setIsCompromised(true);
        $this->em->flush();
    }

    private function issueNewToken(Device $device): string
    {
        $secret = bin2hex(random_bytes(32));
        $device->setRefreshToken(password_hash($secret, PASSWORD_BCRYPT))
            ->setExpiresAt(new \DateTimeImmutable(self::TTL))
            ->setLastUsedAt(new \DateTimeImmutable());

        return $device->getId() . '.' . $secret;
    }

    private function findDeviceByToken(string $token): array
    {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new InvalidRefreshTokenException('Invalid refresh token');
        }
        [$deviceId, $secret] = $parts;

        $device = $this->devices->find($deviceId);
        if (!$device instanceof Device) {
            throw new InvalidRefreshTokenException('Invalid refresh token');
        }

        return [$device, $secret];
    }

    private function enforceDeviceLimit(User $user): void
    {
        $all = $this->devices->findByUserOldestFirst($user);
        $excess = count($all) - (self::MAX_DEVICES - 1);
        for ($i = 0; $i < $excess; $i++) {
            $this->em->remove($all[$i]);
        }
    }
}