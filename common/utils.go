package utils

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"github.com/lestrrat/go-file-rotatelogs"
	"github.com/rifflock/lfshook"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func RandomNum(min, max int64) int64 {
	rand.Seed(time.Now().Unix())
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int63n(max-min) + min
}

func GetLocalIP() string {
	conn, _ := net.Dial("udp", "10.1.1.1:80")
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0]
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IsInsideDocker(pid int64) bool {
	cgroup, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	if strings.Contains(string(cgroup), "docker") {
		return true
	}
	return false
}

func ExecuteCommand(command string, timeout int, cwd string, env []string) (string, string, int) {
	rc := -1
	if f, err := os.Stat(cwd); err != nil || !f.IsDir() {
		msg := fmt.Sprintf("chdir failed, dir %s not exists!", cwd)
		log.Error(msg)
		return "", msg, -500
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	errpipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "cmd stderr pipe error", -500
	}
	outpipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "cmd stdout pipe error", -500
	}
	err = cmd.Start()
	if err != nil {
		return "", "cmd start error", -500
	}

	var mout, merr bytes.Buffer
	go io.Copy(&mout, outpipe)
	go io.Copy(&merr, errpipe)

	done := make(chan error)

	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		rc = 500
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	case err := <-done:
		if err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					rc = status.ExitStatus()
				}
			}
		} else {
			rc = 0
		}
	}
	return mout.String(), merr.String(), rc
}

func InitLogger(path string, reserveDay int) error {
	writer, err := rotatelogs.New(
		path+".%Y%m%d",
		rotatelogs.WithLinkName(path),
		rotatelogs.WithMaxAge(time.Duration(reserveDay)*24*time.Hour),
		rotatelogs.WithRotationTime(24*time.Hour),
	)

	if err != nil {
		return err
	}
	log.AddHook(lfshook.NewHook(lfshook.WriterMap{
		log.DebugLevel: writer,
		log.InfoLevel:  writer,
		log.WarnLevel:  writer,
		log.ErrorLevel: writer,
	}, &log.TextFormatter{}))

	log.SetOutput(ioutil.Discard)
	log.SetLevel(log.DebugLevel)
	return nil
}

func ReadFileAsLines(path string) ([]string, error) {
	var lines []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return lines, err
	}
	lines = strings.Split(string(data), "\n")
	return lines, nil
}

func FileExists(filePath string) bool {
	stat, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	if stat.Mode().IsRegular() {
		return true
	}
	return false
}

func DirExists(filePath string) bool {
	stat, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	if stat.IsDir() {
		return true
	}
	return false
}

func Md5sum(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	digst := fmt.Sprintf("%x", h.Sum(nil))
	return digst, nil
}

func Chunk(whole []time.Time, chunkSize int) [][]time.Time {
	var divided [][]time.Time
	for i := 0; i < len(whole); i += chunkSize {
		end := i + chunkSize

		if end > len(whole) {
			end = len(whole)
		}

		divided = append(divided, whole[i:end])
	}
	return divided
}

func RemoveStrInSlices(list []string, str string) []string {
	var idx int
	for i := range list {
		if list[i] == str {
			idx = i
			break
		}
	}
	return append(list[:idx], list[idx+1:]...)
}

func IfValidIP(ip string) bool {
	ipv4Regex := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	if ipv4Regex.MatchString(ip) {
		return true
	}
	return false
}

