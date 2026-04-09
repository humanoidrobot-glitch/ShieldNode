// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 9626916592678101700687454699154632456537284811699021054622692294828123951264;
    uint256 constant alphay  = 18073620370713873970995889237135852572601963728209605558350049957932254831992;
    uint256 constant betax1  = 10607436905821225409448203417846379678739777315706567883384418405539610813978;
    uint256 constant betax2  = 7770515713271661625257962662634215351625450863787285464780686235707040118553;
    uint256 constant betay1  = 21470274204146540798878449293454021251026985861772542792943799770912656565356;
    uint256 constant betay2  = 14160402683551290478987130726348143251626992609982303437607280763259392599626;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 10225754962243204030068339834862295433836927788776473932114994603265865062753;
    uint256 constant deltax2 = 21851335440278500559140014406942219418954257584985976926290686566756461215441;
    uint256 constant deltay1 = 9003225540944784713709905813607236681398302371551708733696872707495745021485;
    uint256 constant deltay2 = 21533283725129363255396461407322142409393883814593155438188929232483436100749;

    
    uint256 constant IC0x = 16780978978560770923594338972217122922750275010690342390928312351699449927028;
    uint256 constant IC0y = 16352721092689357858535646789717531295728458244086126649179913624241966202824;
    
    uint256 constant IC1x = 3429700134266834900630455735029150647130986857467631922020472420117762718638;
    uint256 constant IC1y = 12442181786542050872825846100889120407063067405767027941562326263263339404384;
    
    uint256 constant IC2x = 13595838122434196460384138896508704311845576994886557389756669815318326320831;
    uint256 constant IC2y = 5679952720711006706276250175279305245104088873449567570717333971895930322760;
    
    uint256 constant IC3x = 5624556314428285447319360850727287285170452496411798644294502183207785780743;
    uint256 constant IC3y = 114525656130093654127411790671747627738420768736996719864640449730428015154;
    
    uint256 constant IC4x = 15530034706597267706094417464274084275381449064398166340063616411013247633308;
    uint256 constant IC4y = 16844337700715424182846815315399464811707481794059263858331306798282282649811;
    
    uint256 constant IC5x = 1479762143422044786896071884472433932624322528659507546760399181412889092302;
    uint256 constant IC5y = 7061820566485370094756076492665032710416362507281282234321904145407570358901;
    
    uint256 constant IC6x = 17516139094432376930455496954987697933735163730589501317415276296070937962009;
    uint256 constant IC6y = 1110834162849461014228050050759817686365384892724974823473289785470941551419;
    
    uint256 constant IC7x = 20871243937714659689556886355745940348821009675334486661389257919223953949794;
    uint256 constant IC7y = 3970316281610734837765756698068109667488020064309406031820808908163961904258;
    
    uint256 constant IC8x = 15999424296647368693631810208170270259475381315678699136113737582627787231549;
    uint256 constant IC8y = 1110696199580301301035405831362368371934145927326331499825030572771770979120;
    
    uint256 constant IC9x = 7971153132064699200000824617925324734957255746605462077616277313586704998245;
    uint256 constant IC9y = 14613580536837801008636766044631698394813170148644616590694672948264602742513;
    
    uint256 constant IC10x = 3198301234963672141487990728825379514458527351332893450480445551518732492501;
    uint256 constant IC10y = 21040611373324739956314455680791515678263759613188951304600721655314855402485;
    
    uint256 constant IC11x = 8535798664976683095182731090958638726770387213726125821009973667672426689871;
    uint256 constant IC11y = 17861627587634007215339919018223190943790016429890140446681821690541226949379;
    
    uint256 constant IC12x = 1729876395524624607007796518092109812264569156344467752826884616960689856401;
    uint256 constant IC12y = 12760709195575232729809658800970169478286167585886548111216719422686493537603;
    
    uint256 constant IC13x = 3239379747180354138518467293989511325612407590582515406494570458365772911117;
    uint256 constant IC13y = 3181523717623953053748035127084388149660436805826391462238816386214407187122;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[13] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
