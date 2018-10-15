<?php declare(strict_types=1);
namespace DOMJudgeBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use JMS\Serializer\Annotation as Serializer;

/**
 * Programming languages in which teams can submit solutions
 * @ORM\Entity()
 * @ORM\Table(name="language", options={"collate"="utf8mb4_unicode_ci", "charset"="utf8mb4"})
 */
class Language
{

    /**
     * @var string
     * @ORM\Id
     * @ORM\Column(type="string", name="langid", length=32, options={"comment"="Unique ID (string)"}, nullable=false)
     * @Serializer\Exclude()
     */
    private $langid;

    /**
     * @var string
     * @ORM\Column(type="string", name="externalid", length=255, nullable=true)
     * @Serializer\SerializedName("id")
     * @Serializer\Groups({"Default", "Nonstrict"})
     */
    private $externalid;

    /**
     * @var string
     * @ORM\Column(type="string", name="name", length=255, options={"comment"="Descriptive language name"}, nullable=false)
     * @Serializer\Groups({"Default", "Nonstrict"})
     */
    private $name;

    /**
     * @var string[]
     * @ORM\Column(type="json_array", length=4294967295, name="extensions", options={"comment"="List of recognized extensions (JSON encoded)"}, nullable=false)
     * @Serializer\Groups({"Nonstrict"})
     * @Serializer\Type("array<string>")
     */
    private $extensions;

    /**
     * @var boolean
     * @ORM\Column(type="boolean", name="allow_submit", options={"comment"="Are submissions accepted in this language?"}, nullable=false)
     * @Serializer\Exclude()
     */
    private $allow_submit = true;

    /**
     * @var boolean
     * @ORM\Column(type="boolean", name="allow_judge", options={"comment"="Are submissions in this language judged?"}, nullable=false)
     * @Serializer\Groups({"Nonstrict"})
     */
    private $allow_judge = true;

    /**
     * @var double
     * @ORM\Column(type="float", name="time_factor", options={"comment"="Language-specific factor multiplied by problem run times"}, nullable=false)
     * @Serializer\Type("double")
     * @Serializer\Groups({"Nonstrict"})
     */
    private $time_factor = 1;

    /**
     * @var string
     * @ORM\Column(type="string", name="compile_script", length=32, options={"comment"="Script to compile source code for this language"}, nullable=true)
     * @Serializer\Exclude()
     */
    private $compile_script;

    /**
     * @var bool
     * @ORM\Column(type="boolean", name="require_entry_point", options={"comment"="Whether submissions require a code entry point to be specified."}, nullable=false)
     * @Serializer\Groups({"Nonstrict"})
     */
    private $require_entry_point = false;

    /**
     * @var string
     * @ORM\Column(type="string", name="entry_point_description", options={"comment"="The description used in the UI for the entry point field."}, nullable=true)
     * @Serializer\Groups({"Nonstrict"})
     */
    private $entry_point_description;

    /**
     * @ORM\ManyToOne(targetEntity="Executable", inversedBy="languages")
     * @ORM\JoinColumn(name="compile_script", referencedColumnName="execid")
     * @Serializer\Exclude()
     */
    private $compile_executable;

    /**
     * @ORM\OneToMany(targetEntity="Submission", mappedBy="language")
     * @Serializer\Exclude()
     */
    private $submissions;

    /**
     * Set langid
     *
     * @param string $langid
     *
     * @return Language
     */
    public function setLangid($langid)
    {
        $this->langid = $langid;

        return $this;
    }

    /**
     * Get langid
     *
     * @return string
     */
    public function getLangid()
    {
        return $this->langid;
    }

    /**
     * Set externalid
     *
     * @param string externalid
     *
     * @return Language
     */
    public function setExternalid(string $externalid)
    {
        $this->externalid = $externalid;

        return $this;
    }

    /**
     * Get externalid
     *
     * @return string
     */
    public function getExternalid()
    {
        return $this->externalid;
    }

    /**
     * Set name
     *
     * @param string $name
     *
     * @return Language
     */
    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set extensions
     *
     * @param string[] $extensions
     *
     * @return Language
     */
    public function setExtensions(array $extensions)
    {
        $this->extensions = $extensions;

        return $this;
    }

    /**
     * Get extensions
     *
     * @return string[]
     */
    public function getExtensions()
    {
        return $this->extensions;
    }

    /**
     * Set allowSubmit
     *
     * @param boolean $allowSubmit
     *
     * @return Language
     */
    public function setAllowSubmit($allowSubmit)
    {
        $this->allow_submit = $allowSubmit;

        return $this;
    }

    /**
     * Get allowSubmit
     *
     * @return boolean
     */
    public function getAllowSubmit()
    {
        return $this->allow_submit;
    }

    /**
     * Set allowJudge
     *
     * @param boolean $allowJudge
     *
     * @return Language
     */
    public function setAllowJudge($allowJudge)
    {
        $this->allow_judge = $allowJudge;

        return $this;
    }

    /**
     * Get allowJudge
     *
     * @return boolean
     */
    public function getAllowJudge()
    {
        return $this->allow_judge;
    }

    /**
     * Set timeFactor
     *
     * @param float $timeFactor
     *
     * @return Language
     */
    public function setTimeFactor($timeFactor)
    {
        $this->time_factor = $timeFactor;

        return $this;
    }

    /**
     * Get timeFactor
     *
     * @return float
     */
    public function getTimeFactor()
    {
        return $this->time_factor;
    }

    /**
     * Set compileScript
     *
     * @param string $compileScript
     *
     * @return Language
     */
    public function setCompileScript($compileScript)
    {
        $this->compile_script = $compileScript;

        return $this;
    }

    /**
     * Get compileScript
     *
     * @return string
     */
    public function getCompileScript()
    {
        return $this->compile_script;
    }

    /**
     * Set requireEntryPoint
     *
     * @param boolean $requireEntryPoint
     *
     * @return Language
     */
    public function setRequireEntryPoint($requireEntryPoint)
    {
        $this->require_entry_point = $requireEntryPoint;

        return $this;
    }

    /**
     * Get requireEntryPoint
     *
     * @return boolean
     */
    public function getRequireEntryPoint()
    {
        return $this->require_entry_point;
    }

    /**
     * Set entryPointDescription
     *
     * @param string $entryPointDescription
     *
     * @return Language
     */
    public function setEntryPointDescription($entryPointDescription)
    {
        $this->entry_point_description = $entryPointDescription;

        return $this;
    }

    /**
     * Get entryPointDescription
     *
     * @return string
     */
    public function getEntryPointDescription()
    {
        return $this->entry_point_description;
    }

    /**
     * Set compileExecutable
     *
     * @param \DOMJudgeBundle\Entity\Executable $compileExecutable
     *
     * @return Language
     */
    public function setCompileExecutable(\DOMJudgeBundle\Entity\Executable $compileExecutable = null)
    {
        $this->compile_executable = $compileExecutable;

        return $this;
    }

    /**
     * Get compileExecutable
     *
     * @return \DOMJudgeBundle\Entity\Executable
     */
    public function getCompileExecutable()
    {
        return $this->compile_executable;
    }
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->submissions = new \Doctrine\Common\Collections\ArrayCollection();
    }

    /**
     * Add submission
     *
     * @param \DOMJudgeBundle\Entity\Submission $submission
     *
     * @return Language
     */
    public function addSubmission(\DOMJudgeBundle\Entity\Submission $submission)
    {
        $this->submissions[] = $submission;

        return $this;
    }

    /**
     * Remove submission
     *
     * @param \DOMJudgeBundle\Entity\Submission $submission
     */
    public function removeSubmission(\DOMJudgeBundle\Entity\Submission $submission)
    {
        $this->submissions->removeElement($submission);
    }

    /**
     * Get submissions
     *
     * @return \Doctrine\Common\Collections\Collection
     */
    public function getSubmissions()
    {
        return $this->submissions;
    }
}
