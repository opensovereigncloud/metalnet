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
	ADD_IFACE_HANDLE_ERR        = 101
	ADD_IFACE_LPM4_ERR          = 102
	ADD_IFACE_LPM6_ERR          = 103
	ADD_IFACE_NO_VFS            = 104
	ADD_IFACE_ALREADY_ALLOCATED = 105
	ADD_IFACE_BAD_DEVICE_NAME   = 106
	ADD_IFACE_VNF_ERR           = 107
	ADD_IFACE_PORT_START_ERR    = 108
	DEL_IFACE_NOT_FOUND         = 131
	GET_IFACE_NOT_FOUND         = 151
	ADD_PREFIX_NO_VM            = 171
	ADD_PREFIX_ROUTE_ERR        = 172
	ADD_PREFIX_VNF_ERR          = 173
	DEL_PREFIX_ROUTE_ERR        = 181
	DEL_PREFIX_NO_VM            = 182
	ADD_ROUTE_NO_VM             = 201
	ADD_ROUTE_EXISTS            = 202
	ADD_ROUTE_SET_ERR           = 203
	ADD_ROUTE_INSERT_ERR        = 204
	DEL_ROUTE_NO_VM             = 231
	DEL_ROUTE_NOT_FOUND         = 232
	DEL_ROUTE_BAD_PORT          = 233
	INIT_RESET_ERR              = 251
	ADD_VIP_NO_VM               = 301
	ADD_VIP_NO_SNAT_DATA        = 302
	ADD_VIP_IP_EXISTS           = 303
	ADD_VIP_SNAT_KEY_ERR        = 304
	ADD_VIP_SNAT_ALLOC          = 305
	ADD_VIP_SNAT_DATA_ERR       = 306
	ADD_VIP_VNF_ERR             = 307
	DEL_VIP_NO_VM               = 331
	DEL_VIP_NO_SNAT_DATA        = 332
	GET_VIP_NO_VM               = 351
	GET_VIP_NO_IP_SET           = 352
	ADD_DNAT_IP_EXISTS          = 371
	ADD_DNAT_KEY_ERR            = 372
	ADD_DNAT_ALLOC              = 373
	ADD_DNAT_DATA_ERR           = 374
	ADD_NAT_NO_VM               = 401
	ADD_NAT_NO_SNAT_DATA        = 402
	ADD_NAT_IP_EXISTS           = 403
	ADD_NAT_SNAT_KEY_ERR        = 404
	ADD_NAT_SNAT_ALLOC          = 405
	ADD_NAT_SNAT_DATA_ERR       = 406
	ADD_NAT_VNF_ERR             = 407
	DEL_NAT_NO_SNAT_DATA        = 431
	DEL_NAT_NO_VM               = 432
	DEL_NAT_NOT_FOUND           = 433
	DEL_NAT_ALREADY_DELETED     = 434
	GET_NAT_ITER_ERR            = 451
	GET_NAT_NO_VM               = 452
	GET_NAT_NO_IP_SET           = 453
	GET_NATINFO_NO_IPV6_SUPPORT = 471
	GET_NATINFO_WRONGTYPE       = 472
	ADD_NEIGHNAT_WRONGTYPE      = 481
	ADD_NEIGHNAT_ALREADY_EXISTS = 482
	ADD_NEIGHNAT_ALLOC          = 483
	DEL_NEIGHNAT_WRONGTYPE      = 491
	DEL_NEIGHNAT_NOT_FOUND      = 492
	ADD_LB_UNSUPP_IP            = 501
	ADD_LB_CREATE_ERR           = 502
	ADD_LB_VNF_ERR              = 503
	ADD_LB_ROUTE_ERR            = 504
	DEL_LB_ID_ERR               = 531
	DEL_LB_BACK_IP_ERR          = 532
	DEL_LB_ROUTE_ERR            = 533
	GET_LB_ID_ERR               = 551
	GET_LB_BACK_IP_ERR          = 552
	ADD_LBVIP_BACKIP_ERR        = 571
	ADD_LBVIP_UNSUPP_IP         = 572
	DEL_LBVIP_BACKIP_ERR        = 581
	DEL_LBVIP_UNSUPP_IP         = 582
	ADD_FWRULE_NO_VM            = 601
	ADD_FWRULE_ALLOC_ERR        = 602
	ADD_FWRULE_NO_DROP_SUPPORT  = 603
	ADD_FWRULE_ID_EXISTS        = 604
	DEL_FWRULE_NO_VM            = 631
	DEL_FWRULE_NOT_FOUND        = 632
	GET_FWRULE_NO_VM            = 651
	GET_FWRULE_NOT_FOUND        = 652
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
