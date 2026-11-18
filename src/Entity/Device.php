<?php

namespace App\Entity;

use App\Repository\DeviceRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: DeviceRepository::class)]
#[ORM\Index(columns: ['last_used_at'])]
class Device
{
    #[ORM\Id]
    #[ORM\Column(length: 32)]
    private string $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $user;

    #[ORM\Column(length: 512, nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(length: 45, nullable: true)]
    private ?string $ip = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $refreshToken = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $previousRefreshToken = null;

    #[ORM\Column]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column]
    private bool $isRevoked = false;

    #[ORM\Column]
    private bool $isCompromised = false;

    #[ORM\Column]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column]
    private \DateTimeImmutable $lastUsedAt;

    public function __construct(User $user)
    {
        $this->id = bin2hex(random_bytes(16));
        $this->user = $user;
        $this->createdAt = $this->lastUsedAt = new \DateTimeImmutable();
        $this->expiresAt = new \DateTimeImmutable();
    }

    public function getId(): string { return $this->id; }
    public function getUser(): User { return $this->user; }

    public function getUserAgent(): ?string { return $this->userAgent; }
    public function setUserAgent(?string $v): static { $this->userAgent = $v !== null ? mb_substr($v, 0, 512) : null; return $this; }

    public function getIp(): ?string { return $this->ip; }
    public function setIp(?string $ip): static { $this->ip = $ip; return $this; }

    public function getRefreshToken(): ?string { return $this->refreshToken; }
    public function setRefreshToken(?string $h): static { $this->refreshToken = $h; return $this; }

    public function getPreviousRefreshToken(): ?string { return $this->previousRefreshToken; }
    public function setPreviousRefreshToken(?string $h): static { $this->previousRefreshToken = $h; return $this; }

    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }
    public function setExpiresAt(\DateTimeImmutable $d): static { $this->expiresAt = $d; return $this; }

    public function isRevoked(): bool { return $this->isRevoked; }
    public function setIsRevoked(bool $v): static { $this->isRevoked = $v; return $this; }

    public function isCompromised(): bool { return $this->isCompromised; }
    public function setIsCompromised(bool $v): static { $this->isCompromised = $v; return $this; }

    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }

    public function getLastUsedAt(): \DateTimeImmutable { return $this->lastUsedAt; }
    public function setLastUsedAt(\DateTimeImmutable $d): static { $this->lastUsedAt = $d; return $this; }

    public function isExpired(): bool { return $this->expiresAt <= new \DateTimeImmutable(); }
}
