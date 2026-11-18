<?php

namespace App\Repository;

use App\Entity\Device;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/** @extends ServiceEntityRepository<Device> */
class DeviceRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Device::class);
    }

    public function findByUserOldestFirst(User $user): array
    {
        return $this->createQueryBuilder('d')
            ->andWhere('d.user = :u')->setParameter('u', $user)
            ->orderBy('d.lastUsedAt', 'ASC')
            ->getQuery()->getResult();
    }

    public function findByUserNewestFirst(User $user): array
    {
        return $this->createQueryBuilder('d')
            ->andWhere('d.user = :u')->setParameter('u', $user)
            ->orderBy('d.lastUsedAt', 'DESC')
            ->getQuery()->getResult();
    }
}
