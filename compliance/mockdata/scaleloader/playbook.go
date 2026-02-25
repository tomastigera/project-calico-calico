package scaleloader

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"time"

	logrus "github.com/sirupsen/logrus"
)

type Playbook struct {
	config         PlaybookCfg
	path           string
	namespace      string
	iteration      int //The iteration of the Steps for churn
	nextsteptime   time.Time
	timestep       time.Duration
	plays          []Play
	scaledPlays    int // For calculating daily rate
	scaledSteps    int
	nonscaledSteps int
	nextSteps      [][]Step
	//netpol       []NetPol
}

func NewPlaybooks(base string, pc PlaybookCfg) ([]*Playbook, error) {
	playbookPath := path.Join(base, pc.Name)
	if info, err := os.Stat(playbookPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Playbook %s at %s does not exist", pc.Name, playbookPath)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("Playbook %s is not a directory", playbookPath)
	}

	playbooks := []*Playbook{}

	for i := 0; i < pc.PlaybookScale; i++ {
		pc.instance = i
		pb, err := generatePlaybookInstance(playbookPath, pc)
		if err != nil {
			return nil, fmt.Errorf("failed to load playbook from config %s", pc.String())
		}
		playbooks = append(playbooks, pb)
	}

	return playbooks, nil
}

func generatePlaybookInstance(playbookPath string, pc PlaybookCfg) (*Playbook, error) {
	ns := pc.Name
	if pc.instance != 0 {
		ns = fmt.Sprintf("%s-%d", pc.Name, pc.instance)
	}

	pb := &Playbook{
		config:         pc,
		path:           playbookPath,
		namespace:      ns,
		iteration:      0,
		scaledPlays:    0,
		scaledSteps:    0,
		nonscaledSteps: 0,
		nextSteps:      [][]Step{},
	}

	log := logrus.WithFields(logrus.Fields{"Playbook": pc.Name, "instance": pc.instance})

	scaledPath := path.Join(playbookPath, "scaled")
	if _, err := os.Stat(scaledPath); err == nil {
		items, err := os.ReadDir(scaledPath)
		if err != nil {
			return nil, fmt.Errorf("failed reading scaled path %s", scaledPath)
		}
		for _, item := range items {
			if item.IsDir() {
				log.Infof("    Loading scaled resource: %s", item.Name())

				pp := path.Join(scaledPath, item.Name())
				p := Play{pathSrc: pp, namespace: pb.namespace}
				p.init, p.steps, err = readPlays(log.WithField("scaled", item.Name()), item.Name(), pp)
				if err != nil {
					return nil, fmt.Errorf("failed to read plays from %s: %v", pp, err)
				}
				for i := 0; i < pc.PlayScale; i++ {
					p.playInstance = i
					pb.plays = append(pb.plays, p.Clone())
					pb.scaledPlays += 1
					pb.scaledSteps += len(p.steps)
				}
			}
		}
	}
	nonscaledPath := path.Join(playbookPath, "nonscaled")
	if _, err := os.Stat(nonscaledPath); err == nil {
		items, err := os.ReadDir(nonscaledPath)
		if err != nil {
			return nil, fmt.Errorf("failed reading nonscaled path %s", nonscaledPath)
		}
		for _, item := range items {
			if item.IsDir() {
				log.Infof("    Loading nonscaled resource: %s", item.Name())

				pp := path.Join(nonscaledPath, item.Name())
				p := Play{pathSrc: pp, namespace: pb.namespace, playInstance: 0}
				p.init, p.steps, err = readPlays(log.WithField("nonscaled", item.Name()), item.Name(), pp)
				if err != nil {
					return nil, fmt.Errorf("failed to read plays from %s: %v", pp, err)
				}
				pb.plays = append(pb.plays, p)
				pb.nonscaledSteps += len(p.steps)
			}
		}
	}

	return pb, nil
}

func readPlays(log *logrus.Entry, scaleName string, playPath string) (init []Step, steps []Step, err error) {
	files, err := os.ReadDir(playPath)
	if err != nil {
		log.Fatal(err)
	}

	steps = []Step{}
	init = []Step{}

	for idx := range 100 {
		stepPrefix := fmt.Sprintf("%02d-", idx)
		for _, f := range files {
			if strings.HasPrefix(f.Name(), stepPrefix) {
				log.Infof("      Reading step: %s", f.Name())
				stepPath := path.Join(playPath, f.Name())
				step, err := readStep(log, scaleName, idx, stepPath)
				if err != nil {
					log.Fatalf("Failed to load pod stage %s", f.Name())
					return nil, nil, fmt.Errorf("Failed to load pod stage %s", f.Name())
				}

				if idx == 0 {
					init = append(init, step)
				} else {
					steps = append(steps, step)
				}
			}
		}
	}
	return init, steps, nil
}

func (p *Playbook) InitializeTimestep(start time.Time) time.Duration {

	steps := p.scaledSteps
	if p.scaledPlays == 0 {
		steps = p.nonscaledSteps
	}

	// Calculate the time between each step to reach the specified churn

	playbookIterationsPerDay := p.config.ChurnRate
	playbookDuration := (time.Hour * 24).Minutes() / playbookIterationsPerDay
	perStepDuration := playbookDuration / float64(steps)
	var err error
	p.timestep, err = time.ParseDuration(fmt.Sprintf("%fm", perStepDuration))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"cfg":   p.config,
			"steps": steps,
		}).Fatal("Parsing duration during timestep calculation failed")
	}
	logrus.WithFields(logrus.Fields{
		"Iter/Day":    playbookIterationsPerDay,
		"PlaybookDur": playbookDuration,
		"stepDur":     perStepDuration,
		"Step":        p.timestep,
	}).Debugf("Playbook")
	p.nextsteptime = start.Add(p.timestep)

	logrus.WithFields(logrus.Fields{"timestep": p.timestep, "playbook": p.config.Name}).Debugf("Playbook")
	return p.timestep
}

func (p *Playbook) GetNextStep() Step {
	p.nextsteptime = p.nextsteptime.Add(p.timestep)

	nsLen := len(p.nextSteps)
	if nsLen == 0 {
		for i := range p.plays {
			if len(p.plays[i].steps) > 0 {
				p.nextSteps = append(p.nextSteps, p.plays[i].GetSteps(p.iteration))
			}
		}
		nsLen = len(p.nextSteps)
		p.iteration += 1
	}
	idx := rand.Intn(nsLen)

	step := p.nextSteps[idx][0]
	// returning the step so remove it from the next ones
	p.nextSteps[idx] = append(p.nextSteps[idx][:0], p.nextSteps[idx][1:]...)
	// if there are no more at an index remove that idx
	if len(p.nextSteps[idx]) == 0 {
		p.nextSteps = append(p.nextSteps[:idx], p.nextSteps[idx+1:]...)
	}

	return step
}
