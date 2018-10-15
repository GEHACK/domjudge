<?php declare(strict_types=1);

namespace DOMJudgeBundle\Controller\API;

use Doctrine\ORM\EntityManagerInterface;
use DOMJudgeBundle\Entity\Executable;
use FOS\RestBundle\Controller\Annotations as Rest;
use FOS\RestBundle\Controller\FOSRestController;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Swagger\Annotations as SWG;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * @Rest\Route("/api/v4/executables", defaults={ "_format" = "json" })
 * @Rest\Prefix("/api/executables")
 * @Rest\NamePrefix("executable_")
 * @SWG\Tag(name="Executables")
 */
class ExecutableController extends FOSRestController
{
    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * ExecutableController constructor.
     * @param EntityManagerInterface $entityManager
     */
    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Get the executable with the given ID
     * @param string $id
     * @return array|string|null
     * @throws \Doctrine\ORM\NonUniqueResultException
     * @Security("has_role('ROLE_JURY') or has_role('ROLE_JUDGEHOST')")
     * @Rest\Get("/{id}")
     * @SWG\Parameter(ref="#/parameters/id")
     * @SWG\Response(
     *     response="200",
     *     description="Information about the requested executable",
     *     @SWG\Schema(type="string", description="Base64-encoded executable contents")
     * )
     */
    public function getNextToJudgeAction(string $id)
    {
        /** @var Executable|null $executable */
        $executable = $this->entityManager->createQueryBuilder()
            ->from('DOMJudgeBundle:Executable', 'e')
            ->select('e')
            ->where('e.execid = :id')
            ->setParameter(':id', $id)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();

        if ($executable === null) {
            throw new NotFoundHttpException(sprintf('Cannot find executable \'%s\'', $id));
        }

        $contents = stream_get_contents($executable->getZipfile());

        return base64_encode($contents);
    }
}
