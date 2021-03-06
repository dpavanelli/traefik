package docker

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/types"
)

const (
	labelDockerNetwork            = "traefik.docker.network"
	labelBackendLoadBalancerSwarm = "traefik.backend.loadbalancer.swarm"
	labelDockerComposeProject     = "com.docker.compose.project"
	labelDockerComposeService     = "com.docker.compose.service"
)

// Map of services properties
// we can get it with label[serviceName][propertyName] and we got the propertyValue
type labelServiceProperties map[string]map[string]string

// Label functions

func getFuncInt64Label(labelName string, defaultValue int64) func(container dockerData) int64 {
	return func(container dockerData) int64 {
		if rawValue, err := getLabel(container, labelName); err == nil {
			value, errConv := strconv.ParseInt(rawValue, 10, 64)
			if errConv == nil {
				return value
			}
			log.Errorf("Unable to parse %q: %q", labelName, rawValue)
		}
		return defaultValue
	}
}

func getFuncMapLabel(labelName string) func(container dockerData) map[string]string {
	return func(container dockerData) map[string]string {
		return parseMapLabel(container, labelName)
	}
}

func parseMapLabel(container dockerData, labelName string) map[string]string {
	if parts, err := getLabel(container, labelName); err == nil {
		if len(parts) == 0 {
			log.Errorf("Could not load %q", labelName)
			return nil
		}

		values := make(map[string]string)
		for _, headers := range strings.Split(parts, "||") {
			pair := strings.SplitN(headers, ":", 2)
			if len(pair) != 2 {
				log.Warnf("Could not load %q: %v, skipping...", labelName, pair)
			} else {
				values[http.CanonicalHeaderKey(strings.TrimSpace(pair[0]))] = strings.TrimSpace(pair[1])
			}
		}

		if len(values) == 0 {
			log.Errorf("Could not load %q", labelName)
			return nil
		}
		return values
	}

	return nil
}

func getFuncStringLabel(label string, defaultValue string) func(container dockerData) string {
	return func(container dockerData) string {
		return getStringLabel(container, label, defaultValue)
	}
}

func getStringLabel(container dockerData, label string, defaultValue string) string {
	if lbl, err := getLabel(container, label); err == nil {
		return lbl
	}
	return defaultValue
}

func getFuncBoolLabel(label string) func(container dockerData) bool {
	return func(container dockerData) bool {
		return getBoolLabel(container, label)
	}
}

func getBoolLabel(container dockerData, label string) bool {
	lbl, err := getLabel(container, label)
	return err == nil && len(lbl) > 0 && strings.EqualFold(strings.TrimSpace(lbl), "true")
}

func getFuncSliceStringLabel(label string) func(container dockerData) []string {
	return func(container dockerData) []string {
		return getSliceStringLabel(container, label)
	}
}

func getSliceStringLabel(container dockerData, labelName string) []string {
	var value []string

	if label, err := getLabel(container, labelName); err == nil {
		value = types.SplitAndTrimString(label)
	}

	if len(value) == 0 {
		log.Debugf("Could not load %v labels", labelName)
	}
	return value
}

// Service label functions

func getFuncServiceSliceStringLabel(labelSuffix string) func(container dockerData, serviceName string) []string {
	return func(container dockerData, serviceName string) []string {
		return getServiceSliceStringLabel(container, serviceName, labelSuffix)
	}
}

func getServiceSliceStringLabel(container dockerData, serviceName string, labelSuffix string) []string {
	if value, ok := getContainerServiceLabel(container, serviceName, labelSuffix); ok {
		return strings.Split(value, ",")
	}
	return getSliceStringLabel(container, types.LabelPrefix+labelSuffix)
}

func getFuncServiceStringLabel(labelSuffix string, defaultValue string) func(container dockerData, serviceName string) string {
	return func(container dockerData, serviceName string) string {
		return getServiceStringLabel(container, serviceName, labelSuffix, defaultValue)
	}
}

func getServiceStringLabel(container dockerData, serviceName string, labelSuffix string, defaultValue string) string {
	if value, ok := getContainerServiceLabel(container, serviceName, labelSuffix); ok {
		return value
	}
	return getStringLabel(container, types.LabelPrefix+labelSuffix, defaultValue)
}

// Base functions

// Gets the entry for a service label searching in all labels of the given container
func getContainerServiceLabel(container dockerData, serviceName string, entry string) (string, bool) {
	value, ok := extractServicesLabels(container.Labels)[serviceName][entry]
	return value, ok
}

// Extract the service labels from container labels of dockerData struct
func extractServicesLabels(labels map[string]string) labelServiceProperties {
	v := make(labelServiceProperties)

	for index, serviceProperty := range labels {
		matches := servicesPropertiesRegexp.FindStringSubmatch(index)
		if matches != nil {
			result := make(map[string]string)
			for i, name := range servicesPropertiesRegexp.SubexpNames() {
				if i != 0 {
					result[name] = matches[i]
				}
			}
			serviceName := result["service_name"]
			if _, ok := v[serviceName]; !ok {
				v[serviceName] = make(map[string]string)
			}
			v[serviceName][result["property_name"]] = serviceProperty
		}
	}

	return v
}

func hasLabel(label string) func(container dockerData) bool {
	return func(container dockerData) bool {
		lbl, err := getLabel(container, label)
		return err == nil && len(lbl) > 0
	}
}

func getLabel(container dockerData, label string) (string, error) {
	if value, ok := container.Labels[label]; ok {
		return value, nil
	}
	return "", fmt.Errorf("label not found: %s", label)
}

func getLabels(container dockerData, labels []string) (map[string]string, error) {
	var globalErr error
	foundLabels := map[string]string{}
	for _, label := range labels {
		foundLabel, err := getLabel(container, label)
		// Error out only if one of them is defined.
		if err != nil {
			globalErr = fmt.Errorf("label not found: %s", label)
			continue
		}
		foundLabels[label] = foundLabel

	}
	return foundLabels, globalErr
}
