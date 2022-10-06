// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dpdk

import (
	"errors"
	"fmt"
)

const (
	ADD                 = 100
	ADD_IPV6_FORMAT     = 101
	ADD_VM_NAME_ERR     = 102
	ADD_VM_LPM4         = 104
	ADD_VM_LPM6         = 105
	ADD_VM_ADD_ROUT4    = 106
	ADD_VM_ADD_ROUT6    = 107
	ADD_VM_NO_VFS       = 108
	ALREADY_ALLOCATED   = 109
	CANT_GET_NAME       = 110
	DEL                 = 150
	DEL_VM_NOT_FND      = 151
	GET_VM_NOT_FND      = 171
	LIST                = 200
	ADD_RT              = 250
	ADD_RT_FAIL4        = 251
	ADD_RT_FAIL6        = 252
	ADD_RT_NO_VNI       = 253
	DEL_RT              = 300
	ADD_NAT             = 350
	ADD_NAT_IP_EXISTS   = 351
	ADD_NAT_ALLOC       = 352
	ADD_NAT_ADD_KEY     = 353
	ADD_NAT_ADD_DATA    = 354
	ADD_DNAT            = 400
	ADD_DNAT_IP_EXISTS  = 401
	ADD_DNAT_ALLOC      = 402
	ADD_DNAT_ADD_KEY    = 403
	ADD_DNAT_ADD_DATA   = 404
	DEL_NAT             = 450
	GET_NAT             = 500
	GET_NAT_NO_IP_SET   = 501
	ADD_LB_VIP          = 550
	ADD_LB_NO_VNI_EXIST = 551
	ADD_LB_UNSUPP_IP    = 552
	DEL_LB_VIP          = 600
	DEL_LB_NO_VNI_EXIST = 601
	DEL_LB_UNSUPP_IP    = 602
	ADD_PFX             = 650
	ADD_PFX_NO_VM       = 651
	ADD_PFX_ROUTE       = 652
	DEL_PFX             = 700
	DEL_PFX_NO_VM       = 701
)

type StatusError struct {
	errorCode int32
	message   string
}

func (s *StatusError) Message() string {
	return s.message
}

func (s *StatusError) ErrorCode() int32 {
	return s.errorCode
}

func (s *StatusError) Error() string {
	if s.message != "" {
		return fmt.Sprintf("[error code %d] %s", s.errorCode, s.message)
	}
	return fmt.Sprintf("error code %d", s.errorCode)
}

func IsStatusErrorCode(err error, errorCodes ...int32) bool {
	statusError := &StatusError{}
	if !errors.As(err, &statusError) {
		return false
	}

	for _, errorCode := range errorCodes {
		if statusError.ErrorCode() == errorCode {
			return true
		}
	}
	return false
}

func IgnoreStatusErrorCode(err error, errorCode int32) error {
	if IsStatusErrorCode(err, errorCode) {
		return nil
	}
	return err
}
