/*
Alize is a free, open tool for speaker recognition

Alize is a development project initiated by the ELISA consortium
  [www.lia.univ-avignon.fr/heberges/ALIZE/ELISA] and funded by the
  French Research Ministry in the framework of the
  TECHNOLANGUE program [www.technolangue.net]
  [www.technolangue.net]

The Alize project team wants to highlight the limits of voice 
  authentication in a forensic context.
  The following paper proposes a good overview of this point:
  [Bonastre J.F., Bimbot F., Boe L.J., Campbell J.P., Douglas D.A., 
  Magrin-chagnolleau I., Person  Authentification by Voice: A Need of 
  Caution, Eurospeech 2003, Genova]
  The conclusion of the paper of the paper is proposed bellow:
  [Currently, it is not possible to completely determine whether the 
  similarity between two recordings is due to the speaker or to other 
  factors, especially when: (a) the speaker does not cooperate, (b) there 
  is no control over recording equipment, (c) recording conditions are not 
  known, (d) one does not know whether the voice was disguised and, to a 
  lesser extent, (e) the linguistic content of the message is not 
  controlled. Caution and judgment must be exercised when applying speaker 
  recognition techniques, whether human or automatic, to account for these 
  uncontrolled factors. Under more constrained or calibrated situations, 
  or as an aid for investigative purposes, judicious application of these 
  techniques may be suitable, provided they are not considered as infallible.
  At the present time, there is no scientific process that enables one to 
  uniquely characterize a person=92s voice or to identify with absolute 
  certainty an individual from his or her voice.]
  Contact Jean-Francois Bonastre for more information about the licence or
  the use of Alize

Copyright (C) 2003-2005
  Laboratoire d'informatique d'Avignon [www.lia.univ-avignon.fr]
  Frederic Wils [frederic.wils@lia.univ-avignon.fr]
  Jean-Francois Bonastre [jean-francois.bonastre@lia.univ-avignon.fr]
      
This file is part of Alize.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#if !defined(ALIZE_SegAbstract_cpp)
#define ALIZE_SegAbstract_cpp

#include "SegAbstract.h"
#include "Exception.h"
#include "SegCluster.h"

using namespace alize;

//-------------------------------------------------------------------------
SegAbstract::SegAbstract(SegServer& ss, unsigned long lc, const String& s,
             const String& sn)
:Object(), _labelCode(lc), _string(s), _srcName(sn), _pServer(&ss)
{ rewind(); }
//-------------------------------------------------------------------------
/*void SegAbstract::assign(const SegAbstract& s)
{
  _begin = s._begin;
  _end = s._end;
  _labelCode = s._labelCode;
  _string = s._string;
  _srcName = s._srcName;
}*/
//------------------------------------------------------------------------
unsigned long SegAbstract::labelCode() const { return _labelCode; }
//-------------------------------------------------------------------------
const String& SegAbstract::string() const { return _string; }
//-------------------------------------------------------------------------
XList& SegAbstract::list() { return _list; }
//-------------------------------------------------------------------------
const XList& SegAbstract::list() const { return _list; }
//-------------------------------------------------------------------------
const String& SegAbstract::sourceName() const { return _srcName; }
//-------------------------------------------------------------------------
SegServer& SegAbstract::getServer() const { return *_pServer; }
//-------------------------------------------------------------------------
void SegAbstract::setLabelCode(unsigned long lc) { _labelCode = lc; }
//-------------------------------------------------------------------------
void SegAbstract::setString(const String& s) { _string = s; }
//-------------------------------------------------------------------------
void SegAbstract::setSourceName(const String& sn) { _srcName = sn; }
//-------------------------------------------------------------------------
void SegAbstract::addOwner(const K&, SegAbstract& o)
{ _ownersVect.addObject(o); }
//-------------------------------------------------------------------------
void SegAbstract::removeOwner(const K&, SegAbstract& o)
{ _ownersVect.removeObject(o); }
//-------------------------------------------------------------------------
void SegAbstract::removeAllOwners(const K&)
{
  /* on retrouve les propriétaires pour couper le lien avec cet objet */
  while(_ownersVect.size() != 0)
    static_cast<SegCluster&>(_ownersVect.getObject(0)).remove(*this);
}
//-------------------------------------------------------------------------
void SegAbstract::rewind() const { _current = 0; }
//-------------------------------------------------------------------------
String SegAbstract::getClassName() const { return "SegAbstract"; }
//-------------------------------------------------------------------------
SegAbstract::~SegAbstract() {}
//-------------------------------------------------------------------------

#endif // !defined(ALIZE_SegAbstract_cpp)
